async function generatePassword() {
    const length       = parseInt(document.getElementById('pwdLength').value);
    const useUpper     = document.getElementById('useUppercase').checked;
    const useLower     = document.getElementById('useLowercase').checked;
    const useNum       = document.getElementById('useNumbers').checked;
    const useSym       = document.getElementById('useSymbols').checked;
    const noAmbiguous  = document.getElementById('noAmbiguous').checked;


    if (!useUpper && !useLower && !useNum && !useSym) {
        alert('Select at least one character type.');
        return;
    }

    try {
        const csrfToken = document.querySelector('meta[name="_csrf"]')?.content
            || document.querySelector('input[name="_csrf"]')?.value;

        const response = await fetch('/api/password/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken
            },
            body: JSON.stringify({
                length: length,
                useUppercase: useUpper,
                useLowercase: useLower,
                useDigits: useNum,
                useSymbols: useSym,
                noAmbiguous: noAmbiguous
            })
        });

        if (!response.ok) {
            const error = await response.json();
            alert(error.error || 'Error generating a new password');
            return;
        }

        const data = await response.json();
        const password = data.password;

        document.getElementById('generatedPassword').textContent = password;
        updateStrength(password, 'generated');

    } catch (error) {
        console.error('Error:', error);
        alert('Error connecting to the server');
    }
}

function copyGeneratedPassword() {
    const pwd = document.getElementById('generatedPassword').textContent;
    if (pwd === '— press Generate —') return;
    navigator.clipboard.writeText(pwd).then(() => {
        const btn  = document.querySelector('.generator__actions .btn-primary');
        const orig = btn.textContent;
        btn.textContent = '✓ Copied';
        setTimeout(() => btn.textContent = orig, 1200);
    });
}

function updateStrength(password, contextId) {
    let score = 0;

    if (password.length >= 8)  score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password))                            score++;
    if (/[^A-Za-z0-9]/.test(password))                     score++;

    const level = score <= 1 ? 1 : score <= 2 ? 2 : score <= 3 ? 3 : 4;

    const labels = { 1: 'Weak', 2: 'Fair', 3: 'Good', 4: 'Strong' };

    const bar   = document.getElementById('strengthBar-' + contextId);
    const label = document.getElementById('strengthLabel-' + contextId);

    if (bar) {
        bar.className = 'strength-bar-container strength-' + level;
    }
    if (label) {
        label.textContent = labels[level];
        label.className   = 'strength-label';
        label.classList.add('strength-' + level);
        const colors = { 1: 'var(--error)', 2: 'var(--warning)', 3: 'var(--accent)', 4: 'var(--success)' };
        label.style.color = colors[level];
    }
}