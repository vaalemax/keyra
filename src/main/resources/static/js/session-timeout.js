/**
 * Session Timeout Warning System
 *
 * Monitors session timeout and warns user before expiration.
 */
(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        sessionTimeout: 30 * 60 * 1000,      // 30 minutes in milliseconds
        warningTime: 5 * 60 * 1000,          // Show warning 5 minutes before expiration
        checkInterval: 30 * 1000,            // Check every 30 seconds
        countdownInterval: 1000              // Update countdown every second
    };

    let warningTimeout = null;
    let expirationTimeout = null;
    let countdownInterval = null;
    let lastActivityTime = Date.now();

    /**
     * Initialize session timeout monitoring.
     */
    function init() {
        // Only initialize on authenticated pages
        if (!document.body.dataset.authenticated) {
            return;
        }

        console.log('[Session] Monitoring initialized');

        // Track user activity
        trackUserActivity();

        // Start monitoring
        resetTimers();

        // Periodic check with server
        setInterval(checkSessionWithServer, CONFIG.checkInterval);
    }

    /**
     * Track user activity to reset timers.
     */
    function trackUserActivity() {
        const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];

        events.forEach(event => {
            document.addEventListener(event, () => {
                const now = Date.now();
                // Only reset if more than 1 minute since last activity
                if (now - lastActivityTime > 60 * 1000) {
                    lastActivityTime = now;
                    resetTimers();
                    console.log('[Session] Activity detected, timers reset');
                }
            }, { passive: true });
        });
    }

    /**
     * Reset warning and expiration timers.
     */
    function resetTimers() {
        // Clear existing timers
        if (warningTimeout) clearTimeout(warningTimeout);
        if (expirationTimeout) clearTimeout(expirationTimeout);
        if (countdownInterval) clearInterval(countdownInterval);

        // Hide warning modal if visible
        hideWarningModal();

        // Set new timers
        const timeUntilWarning = CONFIG.sessionTimeout - CONFIG.warningTime;

        warningTimeout = setTimeout(() => {
            showWarningModal();
        }, timeUntilWarning);

        expirationTimeout = setTimeout(() => {
            handleSessionExpired();
        }, CONFIG.sessionTimeout);
    }

    /**
     * Show session timeout warning modal.
     */
    function showWarningModal() {
        console.log('[Session] Showing timeout warning');

        // Create modal if it doesn't exist
        let modal = document.getElementById('sessionTimeoutModal');
        if (!modal) {
            modal = createWarningModal();
            document.body.appendChild(modal);
        }

        // Start countdown
        startCountdown();

        // Show modal
        modal.classList.add('active');
    }

    /**
     * Hide warning modal.
     */
    function hideWarningModal() {
        const modal = document.getElementById('sessionTimeoutModal');
        if (modal) {
            modal.classList.remove('active');
        }
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
    }

    /**
     * Create warning modal HTML.
     */
    function createWarningModal() {
        const modal = document.createElement('div');
        modal.id = 'sessionTimeoutModal';
        modal.className = 'modal-overlay session-timeout-modal';
        modal.innerHTML = `
            <div class="modal" role="dialog" aria-modal="true" aria-labelledby="sessionTimeoutTitle">
                <div class="modal-header">
                    <h3 id="sessionTimeoutTitle">⏰ Session Expiring Soon</h3>
                </div>
                <div class="modal-body">
                    <p class="timeout-message">
                        Your session will expire in <strong id="countdownTimer">5:00</strong> 
                        due to inactivity.
                    </p>
                    <p class="timeout-submessage">
                        You will be automatically logged out to protect your data.
                    </p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="sessionTimeout.logout()">
                        Logout Now
                    </button>
                    <button type="button" class="btn btn-primary" onclick="sessionTimeout.stayLoggedIn()">
                        Stay Logged In
                    </button>
                </div>
            </div>
        `;
        return modal;
    }

    /**
     * Start countdown timer display.
     */
    function startCountdown() {
        let remainingSeconds = CONFIG.warningTime / 1000;
        const timerEl = document.getElementById('countdownTimer');

        if (countdownInterval) {
            clearInterval(countdownInterval);
        }

        countdownInterval = setInterval(() => {
            remainingSeconds--;

            if (remainingSeconds <= 0) {
                clearInterval(countdownInterval);
                return;
            }

            const minutes = Math.floor(remainingSeconds / 60);
            const seconds = remainingSeconds % 60;
            timerEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }, CONFIG.countdownInterval);
    }

    /**
     * Handle user clicking "Stay Logged In".
     */
    async function stayLoggedIn() {
        console.log('[Session] User chose to stay logged in');

        try {
            const response = await fetch('/api/session/refresh', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': getCsrfToken()
                }
            });

            if (response.ok) {
                console.log('[Session] Session refreshed successfully');
                resetTimers();
                showToast('Session extended successfully', 'success');
            } else {
                throw new Error('Failed to refresh session');
            }
        } catch (error) {
            console.error('[Session] Error refreshing session:', error);
            showToast('Failed to refresh session. Please login again.', 'error');
            setTimeout(() => logout(), 2000);
        }
    }

    /**
     * Handle session expiration.
     */
    function handleSessionExpired() {
        console.log('[Session] Session expired');
        hideWarningModal();
        showToast('Session expired. Redirecting to login...', 'warning');
        setTimeout(() => {
            window.location.href = '/logout';
        }, 2000);
    }

    /**
     * Logout user immediately.
     */
    function logout() {
        console.log('[Session] User logged out');
        window.location.href = '/logout';
    }

    /**
     * Check session status with server.
     */
    async function checkSessionWithServer() {
        try {
            const response = await fetch('/api/session/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': getCsrfToken()
                }
            });

            if (!response.ok) {
                // Session invalid, redirect to login
                handleSessionExpired();
            }
        } catch (error) {
            console.error('[Session] Error checking session:', error);
        }
    }

    /**
     * Get CSRF token from meta tag.
     */
    function getCsrfToken() {
        const meta = document.querySelector('meta[name="_csrf"]');
        return meta ? meta.getAttribute('content') : '';
    }

    /**
     * Show toast notification.
     */
    function showToast(message, type = 'info') {
        // Reuse existing toast system or create simple one
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#f59e0b'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // Public API
    window.sessionTimeout = {
        init: init,
        stayLoggedIn: stayLoggedIn,
        logout: logout,
        resetTimers: resetTimers
    };

    // Auto-initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();