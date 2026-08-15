"""
Accounts app configuration.
"""

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        """Initialize MongoDB connection and create admin user on startup."""
        import mongoengine
        from django.conf import settings
        
        # Connect to MongoDB
        mongoengine.connect(host=settings.MONGODB_URI)
        
        # Create admin user if it doesn't exist
        self._create_admin_user()
    
    def _create_admin_user(self):
        """Create the admin user from environment variables."""
        from django.conf import settings
        from datetime import datetime
        
        try:
            from accounts.models import User
            from accounts.utils.password_hashing import hash_password
            
            admin_username = settings.ADMIN_USERNAME
            admin_email = settings.ADMIN_EMAIL
            admin_password = settings.ADMIN_PASSWORD
            
            # Check if admin exists
            if not User.objects(username=admin_username).first():
                password_hash = hash_password(admin_password)
                admin_user = User(
                    username=admin_username,
                    email=admin_email,
                    display_name='Administrator',
                    password_hash=password_hash,
                    role='admin',
                    email_verified=True,
                    created_at=datetime.utcnow()
                )
                admin_user.save()
                print(f"Admin user '{admin_username}' created successfully.")
        except Exception as e:
            print(f"Could not create admin user: {e}")