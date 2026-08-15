/**
 * Password strength meter for SecureTalk
 * Custom scoring algorithm without external libraries
 */

const BLACKLIST = [
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'letmein', 'login',
  'admin', 'welcome', 'shadow', 'sunshine', 'princess', 'football',
  'baseball', 'iloveyou', 'trustno1', 'superman', 'batman', 'starwars',
  'whatever', 'passw0rd', 'hello123', 'charlie', 'donald', 'password1!',
  'qwerty123', 'asdfgh', 'zxcvbn', '1234567890', 'secret', 'access',
  'michael', 'jennifer', 'jordan', 'hunter', 'buster', 'soccer', 'harley',
  'daniel', 'robert', 'matthew', 'andrew', 'joshua', 'mustang', 'freedom'
];

const SEQUENTIAL_PATTERNS = [
  '012', '123', '234', '345', '456', '567', '678', '789', '890',
  'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk',
  'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst',
  'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
  'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop',
  'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
  'zxc', 'xcv', 'cvb', 'vbn', 'bnm'
];

function scorePassword(password) {
  if (!password) {
    return {
      score: 0,
      label: 'Very weak',
      colour: '#e74c3c',
      feedback: 'Password is required',
      requirements: {
        length: false,
        uppercase: false,
        lowercase: false,
        number: false,
        special: false
      },
      warnings: []
    };
  }

  const passwordLower = password.toLowerCase();

  // Check blacklist first
  if (BLACKLIST.includes(passwordLower)) {
    return {
      score: 0,
      label: 'Very weak',
      colour: '#e74c3c',
      feedback: 'This is a commonly used password',
      requirements: {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password)
      },
      warnings: ['This is a commonly used password']
    };
  }

  let score = 0;
  const feedbackItems = [];
  const warnings = [];

  // Length scoring
  const length = password.length;
  const hasMinLength = length >= 8;

  if (hasMinLength) {
    score += 10;
  } else {
    feedbackItems.push('Use at least 8 characters');
  }

  if (length >= 12) score += 10;
  if (length >= 16) score += 10;
  if (length >= 20) score += 5;

  // Character variety
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password);

  const varietyCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;

  if (hasUpper) {
    score += 15;
  } else {
    feedbackItems.push('Add uppercase letters');
  }

  if (hasLower) {
    score += 15;
  } else {
    feedbackItems.push('Add lowercase letters');
  }

  if (hasDigit) {
    score += 15;
  } else {
    feedbackItems.push('Add numbers');
  }

  if (hasSpecial) {
    score += 20;
  } else {
    feedbackItems.push('Add special characters');
  }

  // Bonus for variety
  if (varietyCount >= 3) {
    score += 5;
  }

  // Penalties
  if (/(.)\1{2,}/.test(password)) {
    score -= 10;
    warnings.push('Avoid repeating characters');
  }

  // Sequential patterns
  for (const pattern of SEQUENTIAL_PATTERNS) {
    if (passwordLower.includes(pattern)) {
      score -= 10;
      warnings.push('Avoid sequential patterns');
      break;
    }
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Determine label and colour
  let label, colour;
  if (score < 40) {
    label = 'Very weak';
    colour = '#e74c3c';
  } else if (score < 60) {
    label = 'Weak';
    colour = '#e67e22';
  } else if (score < 75) {
    label = 'Fair';
    colour = '#f1c40f';
  } else if (score < 90) {
    label = 'Strong';
    colour = '#2ecc71';
  } else {
    label = 'Very strong';
    colour = '#27ae60';
  }

  const feedback = feedbackItems.length > 0
    ? feedbackItems.slice(0, 3).join('. ')
    : 'Great password!';

  return {
    score,
    label,
    colour,
    feedback,
    requirements: {
      length: hasMinLength,
      uppercase: hasUpper,
      lowercase: hasLower,
      number: hasDigit,
      special: hasSpecial
    },
    warnings
  };
}

function createFeedbackHTML(requirements, warnings) {
  const items = [
    { key: 'length', label: '8+ chars', met: requirements.length },
    { key: 'uppercase', label: 'Uppercase', met: requirements.uppercase },
    { key: 'lowercase', label: 'Lowercase', met: requirements.lowercase },
    { key: 'number', label: 'Number', met: requirements.number },
    { key: 'special', label: 'Special', met: requirements.special }
  ];

  let html = items.map(item => {
    const icon = item.met
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

    return `<span class="feedback-item ${item.met ? 'present' : 'missing'}">${icon} ${item.label}</span>`;
  }).join('');

  // Add warnings
  if (warnings.length > 0) {
    html += warnings.map(w =>
      `<span class="feedback-item missing"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> ${w}</span>`
    ).join('');
  }

  return html;
}

function updateMeter(result) {
  const meterFill = document.getElementById('meter-fill');
  const meterLabel = document.getElementById('meter-label');
  const passwordFeedback = document.getElementById('password-feedback');

  if (meterFill) {
    meterFill.style.width = `${result.score}%`;
    meterFill.style.backgroundColor = result.colour;
  }

  if (meterLabel) {
    meterLabel.textContent = result.label;
    meterLabel.style.color = result.colour;
  }

  if (passwordFeedback) {
    passwordFeedback.innerHTML = createFeedbackHTML(result.requirements, result.warnings);
  }
}

function checkPasswordMatch() {
  const password = document.getElementById('password');
  const confirmPassword = document.getElementById('confirm-password');
  const matchIndicator = document.getElementById('password-match');

  if (!password || !confirmPassword || !matchIndicator) return;

  if (confirmPassword.value === '') {
    matchIndicator.innerHTML = '';
    return;
  }

  if (password.value === confirmPassword.value) {
    matchIndicator.innerHTML = '<span class="success">✓ Passwords match</span>';
  } else {
    matchIndicator.innerHTML = '<span class="error">✗ Passwords do not match</span>';
  }
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', function () {
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirm-password');

  if (passwordInput) {
    passwordInput.addEventListener('input', function () {
      const result = scorePassword(this.value);
      updateMeter(result);
      checkPasswordMatch();
    });

    // Initialize with empty state
    if (passwordInput.value) {
      const result = scorePassword(passwordInput.value);
      updateMeter(result);
    }
  }

  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', checkPasswordMatch);
  }
});