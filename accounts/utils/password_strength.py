"""
Password strength checker for SecureTalk.
Custom scoring algorithm without external libraries.
"""

import re

# Common passwords blacklist
BLACKLIST = [
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'letmein', 'login',
    'admin', 'welcome', 'shadow', 'sunshine', 'princess', 'football',
    'baseball', 'iloveyou', 'trustno1', 'superman', 'batman', 'starwars',
    'whatever', 'passw0rd', 'hello123', 'charlie', 'donald', 'password1!',
    'qwerty123', 'asdfgh', 'zxcvbn', '1234567890', 'secret', 'access',
    'michael', 'jennifer', 'jordan', 'hunter', 'buster', 'soccer', 'harley',
    'daniel', 'robert', 'matthew', 'andrew', 'joshua', 'mustang', 'freedom'
]

# Sequential patterns to detect
SEQUENTIAL_PATTERNS = [
    '012', '123', '234', '345', '456', '567', '678', '789', '890',
    'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk',
    'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst',
    'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
    'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop',
    'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
    'zxc', 'xcv', 'cvb', 'vbn', 'bnm'
]


def score_password(password: str) -> dict:
    """
    Score a password and return detailed feedback.
    
    Returns:
        dict with keys: score, label, colour, feedback
    """
    if not password:
        return {
            'score': 0,
            'label': 'Very weak',
            'colour': '#e74c3c',
            'feedback': 'Password is required'
        }
    
    password_lower = password.lower()
    
    # Check blacklist first
    if password_lower in BLACKLIST:
        return {
            'score': 0,
            'label': 'Very weak',
            'colour': '#e74c3c',
            'feedback': 'This is a commonly used password'
        }
    
    score = 0
    feedback_items = []
    
    # Length scoring
    length = len(password)
    if length >= 8:
        score += 10
    else:
        feedback_items.append('Use at least 8 characters')
    
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length >= 20:
        score += 5
    
    # Character variety
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))

    # FIX: Escaped the backslash, brackets, and used double quotes for the string 
    # to avoid conflict with the single quote inside the character class.
    special_regex = r'[!@#$%^&*(),.?":{}|<>_\-+= \[[\]\\\/`~;\'"]'
    has_special = bool(re.search(special_regex, password))

    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    
    if has_upper:
        score += 15
    else:
        feedback_items.append('Add uppercase letters')
    
    if has_lower:
        score += 15
    else:
        feedback_items.append('Add lowercase letters')
    
    if has_digit:
        score += 15
    else:
        feedback_items.append('Add numbers')
    
    if has_special:
        score += 20
    else:
        feedback_items.append('Add special characters')
    
    # Bonus for variety
    if variety_count >= 3:
        score += 5
    
    # Penalties
    # Repeating characters (e.g., 'aaa', '111')
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        feedback_items.append('Avoid repeating characters')
    
    # Sequential patterns
    for pattern in SEQUENTIAL_PATTERNS:
        if pattern in password_lower:
            score -= 10
            feedback_items.append('Avoid sequential patterns')
            break
    
    # Clamp score
    score = max(0, min(100, score))
    
    # Determine label and colour
    if score < 40:
        label = 'Very weak'
        colour = '#e74c3c'
    elif score < 60:
        label = 'Weak'
        colour = '#e67e22'
    elif score < 75:
        label = 'Fair'
        colour = '#f1c40f'
    elif score < 90:
        label = 'Strong'
        colour = '#2ecc71'
    else:
        label = 'Very strong'
        colour = '#27ae60'
    
    # Generate feedback string
    if not feedback_items:
        feedback = 'Great password!'
    else:
        feedback = '. '.join(feedback_items[:3])  # Limit to 3 items
    
    return {
        'score': score,
        'label': label,
        'colour': colour,
        'feedback': feedback
    }