(function () {


    window.onCredPasswordInput = function () {
        const value = document.getElementById('credPassword').value;
        if (typeof updateStrength === 'function') {
            updateStrength(value, 'cred');
        }
        validateNewCredForm();
    };

    window.validateNewCredForm = function () {
        const serviceName = document.getElementById('serviceName').value.trim();
        const username    = document.getElementById('credUsername').value.trim();
        const password    = document.getElementById('credPassword').value;
        const btn         = document.getElementById('submitNewCred');

        btn.disabled = !(serviceName && username && password);
    };

    window.addEventListener('message', function (event) {
        if (event.origin !== window.location.origin) return;
        if (event.data && event.data.type === 'password-generated') {
            const pwdField = document.getElementById('credPassword');
            if (pwdField && document.getElementById('newCredentialModal').classList.contains('active')) {
                pwdField.value = event.data.password;
                onCredPasswordInput();
            }
        }
    });


    window.filterCredentials = function () {
        const query    = document.getElementById('searchInput').value.toLowerCase().trim();
        const category = document.getElementById('filterSelect').value;
        const cards    = document.querySelectorAll('.vault-grid .credential-card');

        cards.forEach(card => {
            const text = card.textContent.toLowerCase();

            const matchesQuery = query === '' || text.includes(query);

            const cardCategory = card.dataset.category || 'other';
            const matchesCategory = category === 'all' || cardCategory === category;

            card.style.display = (matchesQuery && matchesCategory) ? '' : 'none';
        });

        const visibleCards = document.querySelectorAll('.vault-grid .credential-card:not([style*="none"])');
        let emptyFilter = document.getElementById('emptyFilterMsg');

        if (visibleCards.length === 0 && cards.length > 0) {
            if (!emptyFilter) {
                emptyFilter = document.createElement('div');
                emptyFilter.id = 'emptyFilterMsg';
                emptyFilter.className = 'vault-empty';
                emptyFilter.innerHTML = `
                    <span class="vault-empty__icon" style="animation:none">🔍</span>
                    <div class="vault-empty__title">No result</div>
                    <p class="vault-empty__desc">No credentials match the active filters. Try modifying them.</p>
                `;
                document.getElementById('credentialGrid').appendChild(emptyFilter);
            }
            emptyFilter.style.display = '';
        } else if (emptyFilter) {
            emptyFilter.style.display = 'none';
        }
    };

    const originalClose = window.closeModal;
    window.closeModal = function (id) {
        originalClose(id);
        if (id === 'newCredentialModal') {
            document.getElementById('newCredForm').reset();
            document.getElementById('submitNewCred').disabled = true;
            if (typeof updateStrength === 'function') {
                updateStrength('', 'cred');
            }
        }
    };

    window.openEditModal = function(credentialData) {
        document.getElementById('editCredId').value = credentialData.id;
        document.getElementById('editServiceName').value = credentialData.serviceName;
        document.getElementById('editServiceUrl').value = credentialData.url || '';
        document.getElementById('editUsername').value = credentialData.username;
        document.getElementById('editPassword').value = '';
        document.getElementById('editCategory').value = credentialData.category;
        document.getElementById('editNotes').value = credentialData.notes || '';

        const form = document.getElementById('editCredForm');
        form.action = `/vault/edit/${credentialData.id}`;

        openModal('editCredentialModal');
    };

})();

function filterByCategory(category) {
    if (category === 'all') {
        window.location.href = '/vault';
    } else {
        window.location.href = '/vault?category=' + encodeURIComponent(category);
    }
}

function searchCredentials(query) {
    const grid = document.querySelector('.vault-grid');
    if (!grid) return;

    const wrappers = Array.from(grid.querySelectorAll(':scope > div'));
    const searchTerm = query.toLowerCase().trim();

    let visibleCount = 0;
    const visible = [];
    const hidden = [];

    wrappers.forEach(wrapper => {
        if (wrapper.classList.contains('vault-empty') ||
            wrapper.id === 'noResultsMessage') {
            return;
        }

        const text = wrapper.textContent.toLowerCase();
        const matches = searchTerm === '' || text.includes(searchTerm);

        if (matches) {
            wrapper.style.display = '';
            visible.push(wrapper);
            visibleCount++;
        } else {
            wrapper.style.display = 'none';
            hidden.push(wrapper);
        }
    });

    visible.forEach(wrapper => grid.appendChild(wrapper));
    hidden.forEach(wrapper => grid.appendChild(wrapper));

    updateNoResultsMessage(visibleCount, searchTerm);
}

function updateNoResultsMessage(visibleCount, searchTerm) {
    let noResultsMsg = document.getElementById('noResultsMessage');
    const grid = document.querySelector('.vault-grid');

    if (visibleCount === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
            noResultsMsg = document.createElement('div');
            noResultsMsg.id = 'noResultsMessage';
            noResultsMsg.className = 'vault-empty';
            noResultsMsg.style.gridColumn = '1 / -1';
            grid.appendChild(noResultsMsg);
        }

        noResultsMsg.innerHTML = `
            <span class="vault-empty__icon" style="animation:none">🔍</span>
            <div class="vault-empty__title">No credentials found</div>
            <p class="vault-empty__desc">
                No matches for "<strong>${escapeHtml(searchTerm)}</strong>".
                Try a different search term.
            </p>
        `;
        noResultsMsg.style.display = '';
    } else if (noResultsMsg) {
        noResultsMsg.style.display = 'none';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}




document.getElementById('importFile')?.addEventListener('change', function(e) {
    const file = e.target.files[0];
    const submitBtn = document.getElementById('importSubmitBtn');
    const fileInfo = document.getElementById('fileInfo');

    if (file) {
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = formatFileSize(file.size);
        fileInfo.style.display = 'block';

        submitBtn.disabled = false;
    } else {
        fileInfo.style.display = 'none';
        submitBtn.disabled = true;
    }
});

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

document.getElementById('importForm')?.addEventListener('submit', function(e) {
    const replaceCheckbox = document.getElementById('replaceExisting');

    if (replaceCheckbox && replaceCheckbox.checked) {
        if (!confirm('⚠️ This will DELETE ALL your current credentials and replace them with the imported ones. Are you sure?')) {
            e.preventDefault();
            return false;
        }
    }
});