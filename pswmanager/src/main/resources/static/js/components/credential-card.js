document.addEventListener('DOMContentLoaded', function() {
    document.addEventListener('click', function(e) {
        if (e.target.closest('.btn-edit')) {
            const btn = e.target.closest('.btn-edit');

            const credentialData = {
                id: btn.dataset.credId,
                serviceName: btn.dataset.credService,
                username: btn.dataset.credUsername,
                url: btn.dataset.credUrl || '',
                category: btn.dataset.credCategory,
                notes: btn.dataset.credNotes || ''
            };

            openEditModal(credentialData);
        }
    });
});

function openEditModal(credentialData) {
    document.getElementById('editCredId').value = credentialData.id;
    document.getElementById('editServiceName').value = credentialData.serviceName;
    document.getElementById('editServiceUrl').value = credentialData.url;
    document.getElementById('editUsername').value = credentialData.username;
    document.getElementById('editPassword').value = '';
    document.getElementById('editCategory').value = credentialData.category;
    document.getElementById('editNotes').value = credentialData.notes;

    const form = document.getElementById('editCredForm');
    form.action = `/vault/edit/${credentialData.id}`;

    openModal('editCredentialModal');
}

function openEditModalFromCard(btn) {
    const credentialData = {
        id: btn.getAttribute('data-cred-id'),
        serviceName: btn.getAttribute('data-cred-service'),
        username: btn.getAttribute('data-cred-username'),
        url: btn.getAttribute('data-cred-url') || '',
        category: btn.getAttribute('data-cred-category'),
        notes: btn.getAttribute('data-cred-notes') || ''
    };

    openEditModal(credentialData);
}

document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar__menu a');

    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

function togglePasswordVisibilityCard(btn) {
    const password = btn.getAttribute('data-password');
    const row = btn.closest('.credential-card__row');
    const valueDiv = row.querySelector('.credential-card__value--password');

    if (!valueDiv || !password) {
        console.error('Password elements not found');
        return;
    }

    const isHidden = valueDiv.classList.contains('password-hidden');

    if (isHidden) {
        valueDiv.textContent = password;
        valueDiv.classList.remove('password-hidden');
        btn.textContent = '🙈';
        btn.title = 'Hide password';
    } else {
        valueDiv.textContent = '••••••••';
        valueDiv.classList.add('password-hidden');
        btn.textContent = '👁';
        btn.title = 'Show password';
    }
}

function openNotesModal(badge) {
    const notes = badge.getAttribute('data-notes');
    const serviceName = badge.getAttribute('data-service');

    if (!notes) return;

    let modal = document.getElementById('credentialNotesModal');

    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'credentialNotesModal';
        modal.className = 'notes-modal-overlay';
        modal.innerHTML = `
            <div class="notes-modal">
                <div class="notes-modal__header">
                    <h3 class="notes-modal__title" id="notesModalTitle">Notes</h3>
                    <button class="notes-modal__close" onclick="closeNotesModal()">&times;</button>
                </div>
                <div class="notes-modal__body">
                    <div class="notes-modal__content" id="notesModalContent"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeNotesModal();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.classList.contains('active')) {
                closeNotesModal();
            }
        });
    }

    document.getElementById('notesModalTitle').textContent = `Notes - ${serviceName}`;
    document.getElementById('notesModalContent').textContent = notes;

    modal.classList.add('active');
}

function closeNotesModal() {
    const modal = document.getElementById('credentialNotesModal');
    if (modal) {
        modal.classList.remove('active');
    }
}

function togglePasswordVisibility(fieldId, btn) {
    const input = document.getElementById(fieldId);
    if (!input) return;

    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    btn.textContent = isHidden ? '🙈' : '👁';
}


function copyPasswordCard(btn) {
    const password = btn.getAttribute('data-password');

    if (!password) {
        console.error('No password found');
        return;
    }

    navigator.clipboard.writeText(password).then(() => {
        const originalText = btn.textContent;
        const originalTitle = btn.title;

        btn.textContent = '✓';
        btn.title = 'Copied!';
        btn.style.color = 'var(--success)';

        setTimeout(() => {
            btn.textContent = originalText;
            btn.title = originalTitle;
            btn.style.color = '';
        }, 1500);
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy password');
    });
}