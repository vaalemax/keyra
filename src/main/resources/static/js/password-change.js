function checkPasswordStrength() {
    const password = document.getElementById('newPassword').value;
    if (typeof updateStrength === 'function') {
        updateStrength(password, 'newPass');
    }
    validateForm();
}

function checkPasswordMatch() {
    const newPass = document.getElementById('newPassword').value;
    const confirmPass = document.getElementById('confirmPassword').value;
    const indicator = document.getElementById('matchIndicator');

    if (confirmPass.length === 0) {
        indicator.style.display = 'none';
        validateForm();
        return;
    }

    indicator.style.display = 'block';

    if (newPass === confirmPass) {
        indicator.textContent = '✓ Passwords match';
        indicator.style.color = 'var(--success)';
    } else {
        indicator.textContent = '✗ Passwords do not match';
        indicator.style.color = 'var(--error)';
    }

    validateForm();
}

function validateForm() {
    const currentPass = document.getElementById('currentPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirmPass = document.getElementById('confirmPassword').value;
    const submitBtn = document.getElementById('submitBtn');

    const isValid = currentPass.length > 0 &&
        newPass.length >= 8 &&
        confirmPass.length > 0 &&
        newPass === confirmPass;

    submitBtn.disabled = !isValid;
}

document.getElementById('currentPassword').addEventListener('input', validateForm);
document.getElementById('newPassword').addEventListener('input', checkPasswordStrength);
document.getElementById('confirmPassword').addEventListener('input', checkPasswordMatch);

document.getElementById('passwordChangeForm').addEventListener('submit', function(e) {
    console.log('Form submit triggered');

    const currentPass = document.getElementById('currentPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirmPass = document.getElementById('confirmPassword').value;

    console.log('Current password length:', currentPass.length);
    console.log('New password length:', newPass.length);
    console.log('Passwords match:', newPass === confirmPass);

    if (!confirm('⚠️ Are you sure you want to change your master password? You will be logged out and need to sign in again.')) {
        e.preventDefault();
        console.log('Form submission cancelled by user');
    } else {
        console.log('Form submission confirmed - sending to server...');
    }
})