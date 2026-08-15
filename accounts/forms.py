"""
Forms for accounts app.
"""

from django import forms
import re


class RegisterForm(forms.Form):
    """User registration form."""
    
    username = forms.CharField(
        min_length=3,
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Username',
            'autocomplete': 'username'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'Email',
            'autocomplete': 'email'
        })
    )
    display_name = forms.CharField(
        required=False,
        max_length=50,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Display Name (optional)'
        })
    )
    password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Password',
            'autocomplete': 'new-password',
            'id': 'password'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm Password',
            'autocomplete': 'new-password',
            'id': 'confirm-password'
        })
    )
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            raise forms.ValidationError(
                'Username must be 3-30 characters and contain only letters, numbers, and underscores.'
            )
        return username
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError('Passwords do not match.')
        
        return cleaned_data


class LoginForm(forms.Form):
    """User login form."""
    
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Username',
            'autocomplete': 'username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Password',
            'autocomplete': 'current-password'
        })
    )


class ForgotPasswordForm(forms.Form):
    """Forgot password form."""
    
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'Email',
            'autocomplete': 'email'
        })
    )


class ResetPasswordForm(forms.Form):
    """Reset password form."""
    
    password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'New Password',
            'autocomplete': 'new-password',
            'id': 'password'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm New Password',
            'autocomplete': 'new-password',
            'id': 'confirm-password'
        })
    )
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError('Passwords do not match.')
        
        return cleaned_data


class ChangePasswordForm(forms.Form):
    """Change password form."""
    
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Current Password',
            'autocomplete': 'current-password'
        })
    )
    new_password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'New Password',
            'autocomplete': 'new-password',
            'id': 'password'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm New Password',
            'autocomplete': 'new-password',
            'id': 'confirm-password'
        })
    )
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError('Passwords do not match.')
        
        return cleaned_data


class ProfileEditForm(forms.Form):
    """Profile edit form."""
    
    display_name = forms.CharField(
        required=False,
        max_length=50,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Display Name'
        })
    )
    bio = forms.CharField(
        required=False,
        max_length=300,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'placeholder': 'Tell us about yourself...',
            'rows': 4
        })
    )
    theme = forms.ChoiceField(
        choices=[('dark', 'Dark'), ('light', 'Light')],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    notification_sounds = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'})
    )
    show_online_status = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'})
    )


class MFAVerifyForm(forms.Form):
    """MFA verification form."""
    
    code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input mfa-input',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'maxlength': '6'
        })
    )
    
    def clean_code(self):
        code = self.cleaned_data.get('code')
        if not code.isdigit():
            raise forms.ValidationError('Code must contain only numbers.')
        return code
class EmailVerifyForm(forms.Form):
    """Form for email verification code."""
    code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input code-input',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'maxlength': '6',
            'autofocus': True
        })
    )
    
    def clean_code(self):
        code = self.cleaned_data['code'].strip()
        if not code.isdigit() or len(code) != 6:
            raise forms.ValidationError('Please enter a valid 6-digit code.')
        return code