(function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';

    document.documentElement.setAttribute('data-theme', savedTheme);

    updateThemeIcon(savedTheme);

    console.log('[Theme] Initialized with theme:', savedTheme);
})();

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', newTheme);

    localStorage.setItem('theme', newTheme);

    updateThemeIcon(newTheme);

    console.log('[Theme] Switched to:', newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (!icon) return;

    if (theme === 'dark') {
        icon.textContent = '🌙';
    } else {
        icon.textContent = '☀️';
    }
}