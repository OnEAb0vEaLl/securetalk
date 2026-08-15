"""
Admin views for audit and user management.
"""

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_protect
from datetime import datetime, timedelta
import csv
from io import StringIO

from .models import AuditLog
from .utils import log_event
from accounts.models import User
from accounts.middleware import admin_required
from accounts.utils.email_utils import send_admin_action_notice
from chat.models import Room


@admin_required
@require_GET
def admin_users_view(request):
    """Admin user management view."""
    # Get filter parameters
    role_filter = request.GET.get('role', '')
    locked_filter = request.GET.get('locked', '')
    mfa_filter = request.GET.get('mfa', '')
    verified_filter = request.GET.get('verified', '')
    search = request.GET.get('search', '').strip()
    page = int(request.GET.get('page', 1))
    per_page = 50
    
    # Build query
    query = {}
    
    if role_filter:
        query['role'] = role_filter
    
    if locked_filter == 'true':
        query['is_locked'] = True
    elif locked_filter == 'false':
        query['is_locked'] = False
    
    if mfa_filter == 'true':
        query['mfa_methods__not__size'] = 0
    elif mfa_filter == 'false':
        query['mfa_methods__size'] = 0
    
    if verified_filter == 'true':
        query['email_verified'] = True
    elif verified_filter == 'false':
        query['email_verified'] = False
    
    # Get users
    users = User.objects(**query).order_by('-created_at')
    
    # Search filter
    if search:
        users = users.filter(
            __raw__={
                '$or': [
                    {'username': {'$regex': search, '$options': 'i'}},
                    {'email': {'$regex': search, '$options': 'i'}}
                ]
            }
        )
    
    # Pagination
    total = users.count()
    users = users.skip((page - 1) * per_page).limit(per_page)
    total_pages = (total + per_page - 1) // per_page
    
    # Log admin view
    log_event(
        action='ADMIN_VIEW_USERS',
        category='ADMIN',
        request=request,
        actor=request.user,
        severity='INFO'
    )
    
    return render(request, 'dashboard/admin_users.html', {
        'users': users,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'role_filter': role_filter,
        'locked_filter': locked_filter,
        'mfa_filter': mfa_filter,
        'verified_filter': verified_filter,
        'search': search
    })


@admin_required
@csrf_protect
@require_POST
def admin_lock_user_view(request, user_id):
    """Lock a user account."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    # Cannot lock self
    if user.id == request.user.id:
        return JsonResponse({'error': 'Cannot lock your own account'}, status=400)
    
    user.is_locked = True
    user.save()
    
    log_event(
        action='ADMIN_LOCK_USER',
        category='ADMIN',
        request=request,
        actor=request.user,
        target_user=user,
        severity='WARNING'
    )
    
    send_admin_action_notice(
        user.email,
        'Account Locked',
        {'reason': 'Administrative action', 'by': request.user.username}
    )
    
    return JsonResponse({'success': True})


@admin_required
@csrf_protect
@require_POST
def admin_unlock_user_view(request, user_id):
    """Unlock a user account."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    user.is_locked = False
    user.failed_logins = 0
    user.lockout_level = 0
    user.lock_until = None
    user.mfa_failed_attempts = 0
    user.save()
    
    log_event(
        action='ADMIN_UNLOCK_USER',
        category='ADMIN',
        request=request,
        actor=request.user,
        target_user=user,
        severity='INFO'
    )
    
    send_admin_action_notice(
        user.email,
        'Account Unlocked',
        {'by': request.user.username}
    )
    
    return JsonResponse({'success': True})


@admin_required
@csrf_protect
@require_POST
def admin_delete_user_view(request, user_id):
    """Soft delete a user account."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    # Cannot delete self
    if user.id == request.user.id:
        return JsonResponse({'error': 'Cannot delete your own account'}, status=400)
    
    user.is_deleted = True
    user.save()
    
    log_event(
        action='ADMIN_DELETE_USER',
        category='ADMIN',
        request=request,
        actor=request.user,
        target_user=user,
        severity='CRITICAL'
    )
    
    return JsonResponse({'success': True})


@admin_required
@csrf_protect
@require_POST
def admin_force_reset_view(request, user_id):
    """Force a user to reset their password."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    user.force_password_change = True
    user.save()
    
    log_event(
        action='ADMIN_FORCE_RESET',
        category='ADMIN',
        request=request,
        actor=request.user,
        target_user=user,
        severity='WARNING'
    )
    
    send_admin_action_notice(
        user.email,
        'Password Reset Required',
        {'reason': 'Administrative action', 'by': request.user.username}
    )
    
    return JsonResponse({'success': True})


@admin_required
@csrf_protect
@require_POST
def admin_change_role_view(request, user_id):
    """Change a user's role."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    # Cannot change own role
    if user.id == request.user.id:
        return JsonResponse({'error': 'Cannot change your own role'}, status=400)
    
    new_role = request.POST.get('role')
    if new_role not in ['user', 'moderator', 'admin']:
        return JsonResponse({'error': 'Invalid role'}, status=400)
    
    old_role = user.role
    user.role = new_role
    user.save()
    
    log_event(
        action='ADMIN_ROLE_CHANGE',
        category='ADMIN',
        request=request,
        actor=request.user,
        target_user=user,
        details={'old_role': old_role, 'new_role': new_role},
        severity='WARNING'
    )
    
    send_admin_action_notice(
        user.email,
        'Role Changed',
        {'old_role': old_role, 'new_role': new_role, 'by': request.user.username}
    )
    
    return JsonResponse({'success': True})


@admin_required
@require_GET
def admin_rooms_view(request):
    """Admin room management view."""
    # Get filter parameters
    archived_filter = request.GET.get('archived', '')
    room_type_filter = request.GET.get('type', '')
    search = request.GET.get('search', '').strip()
    page = int(request.GET.get('page', 1))
    per_page = 50
    
    # Build query
    query = {}
    
    if archived_filter == 'true':
        query['is_archived'] = True
    elif archived_filter == 'false':
        query['is_archived'] = False
    
    if room_type_filter:
        query['room_type'] = room_type_filter
    
    # Get rooms
    rooms = Room.objects(**query).order_by('-created_at')
    
    # Search filter
    if search:
        rooms = rooms.filter(name__icontains=search)
    
    # Pagination
    total = rooms.count()
    rooms = rooms.skip((page - 1) * per_page).limit(per_page)
    total_pages = (total + per_page - 1) // per_page
    
    return render(request, 'dashboard/admin_rooms.html', {
        'rooms': rooms,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'archived_filter': archived_filter,
        'room_type_filter': room_type_filter,
        'search': search
    })


@admin_required
@csrf_protect
@require_POST
def admin_archive_room_view(request, room_slug):
    """Archive a room."""
    try:
        room = Room.objects.get(slug=room_slug)
    except Room.DoesNotExist:
        return JsonResponse({'error': 'Room not found'}, status=404)
    
    room.is_archived = True
    room.save()
    
    log_event(
        action='ADMIN_ARCHIVE_ROOM',
        category='ADMIN',
        request=request,
        actor=request.user,
        details={'room_name': room.name},
        severity='INFO'
    )
    
    return JsonResponse({'success': True})


@admin_required
@csrf_protect
@require_POST
def admin_restore_room_view(request, room_slug):
    """Restore an archived room."""
    try:
        room = Room.objects.get(slug=room_slug)
    except Room.DoesNotExist:
        return JsonResponse({'error': 'Room not found'}, status=404)
    
    room.is_archived = False
    room.save()
    
    log_event(
        action='ADMIN_RESTORE_ROOM',
        category='ADMIN',
        request=request,
        actor=request.user,
        details={'room_name': room.name},
        severity='INFO'
    )
    
    return JsonResponse({'success': True})


@admin_required
@require_GET
def audit_log_view(request):
    """Admin audit log view."""
    # Get filter parameters
    category = request.GET.getlist('category')
    severity = request.GET.getlist('severity')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    actor = request.GET.get('actor', '').strip()
    action = request.GET.get('action', '').strip()
    ip_address = request.GET.get('ip', '').strip()
    page = int(request.GET.get('page', 1))
    per_page = 50
    
    # Build query
    query = {}
    
    if category:
        query['category__in'] = category
    
    if severity:
        query['severity__in'] = severity
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query['timestamp__gte'] = from_date
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query['timestamp__lt'] = to_date
        except ValueError:
            pass
    
    if actor:
        query['actor_username__icontains'] = actor
    
    if action:
        query['action__icontains'] = action
    
    if ip_address:
        query['ip_address__icontains'] = ip_address
    
    # Get logs
    logs = AuditLog.objects(**query).order_by('-timestamp')
    
    # Pagination
    total = logs.count()
    logs = logs.skip((page - 1) * per_page).limit(per_page)
    total_pages = (total + per_page - 1) // per_page
    
    # Log admin view
    log_event(
        action='ADMIN_VIEW_LOGS',
        category='ADMIN',
        request=request,
        actor=request.user,
        severity='INFO'
    )
    
    # Available categories and actions for filters
    categories = ['AUTH', 'MFA', 'ACCOUNT', 'ROOM', 'MESSAGE', 'ADMIN', 'SECURITY']
    severities = ['INFO', 'WARNING', 'CRITICAL']
    
    return render(request, 'dashboard/admin_audit.html', {
        'logs': logs,
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'categories': categories,
        'severities': severities,
        'selected_categories': category,
        'selected_severities': severity,
        'date_from': date_from,
        'date_to': date_to,
        'actor_filter': actor,
        'action_filter': action,
        'ip_filter': ip_address
    })


@admin_required
@require_GET
def audit_export_view(request):
    """Export audit logs as CSV."""
    # Get same filters as audit_log_view
    category = request.GET.getlist('category')
    severity = request.GET.getlist('severity')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    actor = request.GET.get('actor', '').strip()
    action = request.GET.get('action', '').strip()
    ip_address = request.GET.get('ip', '').strip()
    
    # Build query
    query = {}
    
    if category:
        query['category__in'] = category
    if severity:
        query['severity__in'] = severity
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query['timestamp__gte'] = from_date
        except ValueError:
            pass
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query['timestamp__lt'] = to_date
        except ValueError:
            pass
    if actor:
        query['actor_username__icontains'] = actor
    if action:
        query['action__icontains'] = action
    if ip_address:
        query['ip_address__icontains'] = ip_address
    
    # Get logs (limit to 10000 for safety)
    logs = AuditLog.objects(**query).order_by('-timestamp')[:10000]
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'Timestamp', 'Category', 'Severity', 'Action',
        'Actor', 'Target', 'IP Address', 'User Agent', 'Details'
    ])
    
    # Data rows
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat(),
            log.category,
            log.severity,
            log.action,
            log.actor_username or '',
            log.target_username or '',
            log.ip_address or '',
            log.user_agent or '',
            str(log.details) if log.details else ''
        ])
    
    # Create response
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    return response


@admin_required
@require_GET
def audit_detail_view(request, log_id):
    """Get audit log detail as JSON."""
    try:
        log = AuditLog.objects.get(id=log_id)
    except AuditLog.DoesNotExist:
        return JsonResponse({'error': 'Log not found'}, status=404)
    
    return JsonResponse({
        'id': str(log.id),
        'timestamp': log.timestamp.isoformat(),
        'category': log.category,
        'severity': log.severity,
        'action': log.action,
        'actor_username': log.actor_username,
        'target_username': log.target_username,
        'ip_address': log.ip_address,
        'user_agent': log.user_agent,
        'details': log.details
    })