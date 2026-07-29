document.getElementById('totpCode')?.addEventListener('input', function(e) {
    this.value = this.value.replace(/\D/g, '').substring(0, 6);
});

document.getElementById('backupCode')?.addEventListener('input', function(e) {
    this.value = this.value.replace(/\D/g, '').substring(0, 8);
});

function toggleBackupForm() {
    const totpForm = document.getElementById('totpForm');
    const backupForm = document.getElementById('backupForm');
    const totpLink = document.querySelector('.totp-link');

    if (backupForm.classList.contains('active')) {
        backupForm.classList.remove('active');
        totpForm.classList.remove('hidden');
        totpLink.style.display = 'block';
        document.getElementById('totpCode').focus();
    } else {
        totpForm.classList.add('hidden');
        backupForm.classList.add('active');
        totpLink.style.display = 'none';
        document.getElementById('backupCode').focus();
    }
}