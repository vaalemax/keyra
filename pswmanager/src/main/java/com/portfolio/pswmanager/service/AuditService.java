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

@Service
@RequiredArgsConstructor
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository auditLogRepository;

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

    // logs an action with entity reference (e.g., credential ID)
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

    @Transactional(readOnly = true)
    public Page<AuditLog> getUserAuditLogs(Long userId, Pageable pageable) {
        log.debug("Retrieving audit logs for user ID: {}", userId);
        return auditLogRepository.findByUserIdOrderByTimestampDesc(userId, pageable);
    }

    // extracts IP address from HTTP request
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

    // extracts User-Agent from HTTP request
    public String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        // Truncate if too long
        if (userAgent != null && userAgent.length() > 500) {
            userAgent = userAgent.substring(0, 500);
        }
        return userAgent;
    }

    // count by action type)
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

    @Transactional(readOnly = true)
    public void auditVaultSuccess(AuditLog.AuditAction auditAction, String entityType, User user,
                                  Long entityId, String message, String clientIp, String userAgent) {
        this.logActionWithEntity(
                user,
                auditAction,
                AuditLog.AuditStatus.SUCCESS,
                entityType,
                entityId,
                message,
                clientIp,
                userAgent
        );
    }

    @Transactional(readOnly = true)
    public void auditVaultFailure(AuditLog.AuditAction auditAction, String entityType, User user,
                                  Long entityId, String reason, String clientIp, String userAgent){
        this.logActionWithEntity(
                user,
                auditAction,
                AuditLog.AuditStatus.FAILURE,
                entityType,
                entityId,
                reason,
                clientIp,
                userAgent
        );
    }
}