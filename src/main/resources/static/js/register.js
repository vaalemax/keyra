(function () {

    const masterInput   = document.getElementById('masterPassword');
    const confirmInput  = document.getElementById('confirmPassword');
    const confirmHint   = document.getElementById('confirmHint');
    const submitBtn     = document.getElementById('submitBtn');

    const REQUIREMENTS = {
        'req-length':  { test: v => v.length >= 8            },
        'req-upper':   { test: v => /[A-Z]/.test(v)          },
        'req-lower':   { test: v => /[a-z]/.test(v)          },
        'req-number':  { test: v => /[0-9]/.test(v)          },
        'req-special': { test: v => /[^A-Za-z0-9]/.test(v)   }
    };

    let allRequirementsMet = false;
    let passwordsMatch     = false;

    window.onMasterPasswordInput = function () {
        const value = masterInput.value;

        allRequirementsMet = true;

        Object.keys(REQUIREMENTS).forEach(id => {
            const el   = document.getElementById(id);
            const icon = el.querySelector('.req-icon');
            const ok   = REQUIREMENTS[id].test(value);

            el.classList.toggle('satisfied', ok);
            icon.textContent = ok ? '✔' : '✕';

            if (!ok) allRequirementsMet = false;
        });

        if (typeof updateStrength === 'function') {
            updateStrength(value, 'new');
        }

        if (confirmInput.value.length > 0) {
            onConfirmPasswordInput();
        }

        updateSubmitButton();
    };

    window.onConfirmPasswordInput = function () {
        const master  = masterInput.value;
        const confirm = confirmInput.value;

        if (confirm.length === 0) {
            passwordsMatch          = false;
            confirmHint.className   = 'confirm-hint';
            confirmHint.textContent = '';
            confirmInput.classList.remove('input-match', 'input-mismatch');

        } else if (master === confirm) {
            passwordsMatch          = true;
            confirmHint.className   = 'confirm-hint visible match';
            confirmHint.textContent = '✔ Passwords match';
            confirmInput.classList.remove('input-mismatch');
            confirmInput.classList.add('input-match');

        } else {
            passwordsMatch          = false;
            confirmHint.className   = 'confirm-hint visible mismatch';
            confirmHint.textContent = '✕ Passwords do not match';
            confirmInput.classList.remove('input-match');
            confirmInput.classList.add('input-mismatch');
        }

        updateSubmitButton();
    };

    function updateSubmitButton() {
        const usernameOk = document.getElementById('username').value.trim().length > 0;
        submitBtn.disabled = !(usernameOk && allRequirementsMet && passwordsMatch);
    }

    window.togglePasswordVisibility = function (fieldId, btn) {
        const input    = document.getElementById(fieldId);
        const isHidden = input.type === 'password';

        input.type      = isHidden ? 'text'     : 'password';
        btn.textContent = isHidden ? '🙈'       : '👁';
        btn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
        input.focus();
    };

    document.getElementById('username').addEventListener('input', updateSubmitButton);

})();