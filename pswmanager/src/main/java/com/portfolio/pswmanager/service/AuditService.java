package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for audit logging.
 * All audit operations are executed asynchronously and in separate transactions
 * to avoid impacting main application flow.
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository auditLogRepository;

    /**
     * Logs a user action.
     * Executed asynchronously to not block the main thread.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logAction(
            User user,
            AuditLog.AuditAction action,
            AuditLog.AuditStatus status,
            String details,
            String ipAddress,
            String userAgent
    ) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUser(user);
            auditLog.setAction(action);
            auditLog.setStatus(status);
            auditLog.setDetails(details);
            auditLog.setIpAddress(ipAddress);
            auditLog.setUserAgent(userAgent);

            auditLogRepository.save(auditLog);

            log.debug("Audit log created - user: {}, action: {}, status: {}",
                    user != null ? user.getUsername() : "SYSTEM",
                    action,
                    status);

        } catch (Exception e) {
            // Don't throw exception - audit failures should not break main flow
            log.error("Failed to create audit log - action: {}, user: {}",
                    action,
                    user != null ? user.getUsername() : "SYSTEM",
                    e);
        }
    }

    /**
     * Logs an action with entity reference (e.g., credential ID).
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logActionWithEntity(
            User user,
            AuditLog.AuditAction action,
            AuditLog.AuditStatus status,
            String entityType,
            Long entityId,
            String details,
            String ipAddress,
            String userAgent
    ) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUser(user);
            auditLog.setAction(action);
            auditLog.setStatus(status);
            auditLog.setEntityType(entityType);
            auditLog.setEntityId(entityId);
            auditLog.setDetails(details);
            auditLog.setIpAddress(ipAddress);
            auditLog.setUserAgent(userAgent);

            auditLogRepository.save(auditLog);

            log.debug("Audit log created - user: {}, action: {}, entity: {} (ID: {})",
                    user != null ? user.getUsername() : "SYSTEM",
                    action,
                    entityType,
                    entityId);

        } catch (Exception e) {
            log.error("Failed to create audit log with entity - action: {}, user: {}",
                    action,
                    user != null ? user.getUsername() : "SYSTEM",
                    e);
        }
    }

    /**
     * Logs a failed login attempt (user may not exist).
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logFailedLogin(
            String username,
            String details,
            String ipAddress,
            String userAgent
    ) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUser(null); // User doesn't exist or wrong password
            auditLog.setAction(AuditLog.AuditAction.LOGIN_FAILURE);
            auditLog.setStatus(AuditLog.AuditStatus.FAILURE);
            auditLog.setDetails("Username: " + username + " - " + details);
            auditLog.setIpAddress(ipAddress);
            auditLog.setUserAgent(userAgent);

            auditLogRepository.save(auditLog);

            log.warn("Failed login attempt logged - username: {}, IP: {}", username, ipAddress);

        } catch (Exception e) {
            log.error("Failed to log failed login attempt for username: {}", username, e);
        }
    }

    /**
     * Retrieves audit logs for a specific user.
     */
    @Transactional(readOnly = true)
    public Page<AuditLog> getUserAuditLogs(Long userId, Pageable pageable) {
        log.debug("Retrieving audit logs for user ID: {}", userId);
        return auditLogRepository.findByUserIdOrderByTimestampDesc(userId, pageable);
    }

    /**
     * Retrieves recent audit logs for a user (last 10).
     */
    @Transactional(readOnly = true)
    public List<AuditLog> getRecentUserAuditLogs(Long userId) {
        log.debug("Retrieving recent audit logs for user ID: {}", userId);
        return auditLogRepository.findTop10ByUserIdOrderByTimestampDesc(userId);
    }

    /**
     * Checks for suspicious activity (e.g., multiple failed logins).
     */
    @Transactional(readOnly = true)
    public boolean hasSuspiciousActivity(String username, int maxAttempts, int timeWindowMinutes) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(timeWindowMinutes);
        List<AuditLog> failedAttempts = auditLogRepository.findFailedLoginAttempts(username, since);

        boolean suspicious = failedAttempts.size() >= maxAttempts;

        if (suspicious) {
            log.warn("Suspicious activity detected for username: {} - {} failed login attempts in {} minutes",
                    username, failedAttempts.size(), timeWindowMinutes);
        }

        return suspicious;
    }

    /**
     * Cleanup old audit logs (run periodically via scheduled task).
     */
    @Transactional
    public void cleanupOldLogs(int retentionDays) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
        log.info("Cleaning up audit logs older than {} days", retentionDays);

        try {
            auditLogRepository.deleteByTimestampBefore(cutoffDate);
            log.info("Audit log cleanup completed");
        } catch (Exception e) {
            log.error("Error during audit log cleanup", e);
        }
    }

    // ═══════════════════════════════════════════════════════
    // UTILITY METHODS
    // ═══════════════════════════════════════════════════════

    /**
     * Extracts IP address from HTTP request.
     */
    public String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // If multiple IPs (proxy chain), take the first one
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    /**
     * Extracts User-Agent from HTTP request.
     */
    public String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        // Truncate if too long
        if (userAgent != null && userAgent.length() > 500) {
            userAgent = userAgent.substring(0, 500);
        }
        return userAgent;
    }

    /**
     * Get action statistics (count by action type).
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getActionStatistics(Long userId) {
        log.debug("Calculating action statistics for user ID: {}", userId);

        List<AuditLog> logs = auditLogRepository.findByUserIdOrderByTimestampDesc(
                userId,
                PageRequest.of(0, 1000)  // Last 1000 events
        ).getContent();

        return logs.stream()
                .collect(Collectors.groupingBy(
                        log -> log.getAction().name(),
                        Collectors.counting()
                ));
    }

    /**
     * Get daily activity statistics for the last N days.
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getDailyActivityStats(Long userId, int days) {
        log.debug("Calculating daily activity stats for user ID: {} (last {} days)", userId, days);

        LocalDateTime since = LocalDateTime.now().minusDays(days);

        List<AuditLog> logs = auditLogRepository.findByUserIdAndTimestampAfter(userId, since);

        return logs.stream()
                .collect(Collectors.groupingBy(
                        log -> log.getTimestamp().toLocalDate().toString(),
                        Collectors.counting()
                ));
    }
}