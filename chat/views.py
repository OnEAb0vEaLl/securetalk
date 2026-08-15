"""
Views for chat app.
"""

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_protect
from django.utils.text import slugify
from passlib.hash import bcrypt
from datetime import datetime
import uuid
import re

from .models import Room, Message
from accounts.models import User
from accounts.middleware import login_required
from audit.utils import log_event


@login_required
@require_GET
def lobby_view(request):
    """Chat lobby - room discovery and joined rooms."""
    user = request.user
    
    # Get public rooms (not archived)
    public_rooms = Room.objects(
        room_type='public',
        is_archived=False
    ).order_by('-member_count', '-created_at')[:50]
    
    # Get rooms the user has joined
    joined_rooms = Room.objects(
        members=user,
        is_archived=False
    ).order_by('-created_at')
    
    # Calculate stats
    total_rooms = Room.objects(is_archived=False).count()
    total_users_online = User.objects(
        last_seen__gte=datetime.utcnow() - __import__('datetime').timedelta(minutes=3)
    ).count()
    messages_today = Message.objects(
        created_at__gte=datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    
    return render(request, 'chat/lobby.html', {
        'public_rooms': public_rooms,
        'joined_rooms': joined_rooms,
        'total_rooms': total_rooms,
        'total_users_online': total_users_online,
        'messages_today': messages_today
    })


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def create_room_view(request):
    """Create a new chat room."""
    if request.method == 'GET':
        return render(request, 'chat/create_room.html')
    
    name = request.POST.get('name', '').strip()
    description = request.POST.get('description', '').strip()
    room_type = request.POST.get('room_type', 'public')
    password = request.POST.get('password', '').strip()
    banner_color = request.POST.get('banner_color', '#6c5ce7')
    
    # Validate name
    if not name or not re.match(r'^[a-zA-Z0-9 _-]{3,50}$', name):
        return render(request, 'chat/create_room.html', {
            'error': 'Room name must be 3-50 characters and contain only letters, numbers, spaces, underscores, and hyphens.',
            'name': name,
            'description': description
        })
    
    # Check uniqueness
    if Room.objects(name__iexact=name).first():
        return render(request, 'chat/create_room.html', {
            'error': 'A room with this name already exists.',
            'name': name,
            'description': description
        })
    
    # Generate slug
    base_slug = slugify(name)
    slug = f"{base_slug}-{uuid.uuid4().hex[:8]}"
    
    # Hash password if private
    password_hash = None
    if room_type == 'private':
        if not password or len(password) < 4:
            return render(request, 'chat/create_room.html', {
                'error': 'Private rooms require a password of at least 4 characters.',
                'name': name,
                'description': description
            })
        password_hash = bcrypt.using(rounds=12).hash(password)
    
    # Validate banner color
    if not re.match(r'^#[0-9a-fA-F]{6}$', banner_color):
        banner_color = '#6c5ce7'
    
    # Create room
    room = Room(
        name=name,
        slug=slug,
        description=description[:300] if description else '',
        room_type=room_type,
        password_hash=password_hash,
        owner=request.user,
        members=[request.user],
        member_count=1,
        banner_color=banner_color,
        created_at=datetime.utcnow()
    )
    room.save()
    
    log_event(
        action='ROOM_CREATE',
        category='ROOM',
        request=request,
        actor=request.user,
        details={'room_name': name, 'room_type': room_type},
        severity='INFO'
    )
    
    return redirect('room', room_slug=slug)


@login_required
@require_GET
def room_view(request, room_slug):
    """View a chat room."""
    room = Room.objects(slug=room_slug, is_archived=False).first()
    
    if not room:
        return render(request, 'chat/room.html', {
            'error': 'Room not found.'
        })
    
    user = request.user
    is_member = user in room.members
    
    # If private and not a member, show password prompt
    if room.is_private and not is_member:
        return render(request, 'chat/room.html', {
            'room': room,
            'show_password_form': True
        })
    
    # If public and not a member, auto-join
    if not is_member:
        room.members.append(user)
        room.member_count = len(room.members)
        room.save()
        
        log_event(
            action='ROOM_JOIN',
            category='ROOM',
            request=request,
            actor=user,
            details={'room_name': room.name},
            severity='INFO'
        )
    
    # Get online members
    online_members = [m for m in room.members if m.is_online]
    offline_members = [m for m in room.members if not m.is_online]
    
    return render(request, 'chat/room.html', {
        'room': room,
        'is_owner': room.owner.id == user.id,
        'is_moderator': user in room.moderators,
        'online_members': online_members,
        'offline_members': offline_members
    })


@login_required
@csrf_protect
@require_POST
def join_private_room_view(request, room_slug):
    """Join a private room with password."""
    room = Room.objects(slug=room_slug, is_archived=False).first()
    
    if not room:
        return redirect('lobby')
    
    if not room.is_private:
        return redirect('room', room_slug=room_slug)
    
    user = request.user
    
    # Already a member
    if user in room.members:
        return redirect('room', room_slug=room_slug)
    
    password = request.POST.get('password', '')
    
    # Verify password
    if not room.password_hash or not bcrypt.verify(password, room.password_hash):
        log_event(
            action='ROOM_PASSWORD_FAIL',
            category='ROOM',
            request=request,
            actor=user,
            details={'room_name': room.name},
            severity='WARNING'
        )
        
        return render(request, 'chat/room.html', {
            'room': room,
            'show_password_form': True,
            'error': 'Incorrect password.'
        })
    
    # Join room
    room.members.append(user)
    room.member_count = len(room.members)
    room.save()
    
    log_event(
        action='ROOM_JOIN_PRIVATE',
        category='ROOM',
        request=request,
        actor=user,
        details={'room_name': room.name},
        severity='INFO'
    )
    
    return redirect('room', room_slug=room_slug)


@login_required
@csrf_protect
@require_POST
def leave_room_view(request, room_slug):
    """Leave a chat room."""
    room = Room.objects(slug=room_slug).first()
    
    if not room:
        return redirect('lobby')
    
    user = request.user
    
    if user not in room.members:
        return redirect('lobby')
    
    # Remove from members
    room.members = [m for m in room.members if m.id != user.id]
    room.member_count = len(room.members)
    
    # Transfer ownership if owner leaves
    if room.owner.id == user.id:
        if room.members:
            # Transfer to oldest remaining member
            room.owner = room.members[0]
        else:
            # Archive if no members left
            room.is_archived = True
    
    room.save()
    
    log_event(
        action='ROOM_LEAVE',
        category='ROOM',
        request=request,
        actor=user,
        details={'room_name': room.name},
        severity='INFO'
    )
    
    return redirect('lobby')


@login_required
@csrf_protect
@require_POST
def delete_room_view(request, room_slug):
    """Delete (archive) a chat room."""
    room = Room.objects(slug=room_slug).first()
    
    if not room:
        return redirect('lobby')
    
    user = request.user
    
    # Only owner or admin can delete
    if room.owner.id != user.id and user.role != 'admin':
        return redirect('room', room_slug=room_slug)
    
    # Soft archive
    room.is_archived = True
    room.save()
    
    log_event(
        action='ROOM_DELETE',
        category='ROOM',
        request=request,
        actor=user,
        details={'room_name': room.name},
        severity='INFO'
    )
    
    return redirect('lobby')