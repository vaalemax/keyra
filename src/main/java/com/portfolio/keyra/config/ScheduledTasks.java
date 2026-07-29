package com.portfolio.keyra.config;

import com.portfolio.keyra.repository.AuditLogRepository;
import com.portfolio.keyra.service.RateLimitService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class ScheduledTasks {

    private final AuditLogRepository auditLogRepository;

    private final RateLimitService rateLimitService;

    private static final Logger log = LoggerFactory.getLogger(ScheduledTasks.class);

    @Value("${audit-log.retention-days:90}")
    private int retentionDays;

    public ScheduledTasks(AuditLogRepository auditLogRepository,
                          RateLimitService rateLimitService) {
        this.auditLogRepository = auditLogRepository;
        this.rateLimitService = rateLimitService;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void clearRateLimitCache() {
        log.info("Starting scheduled rate limit cache cleanup");
        int sizeBefore = rateLimitService.getCacheSize();
        rateLimitService.clearCache();
        log.info("Rate limit cache cleared - removed {} entries", sizeBefore);
    }

    @Scheduled(cron = "0 0 3 * * *")
    public void purgeOldAuditLogs() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        log.info("Purging audit logs older than {}", cutoff);
        long deleted = auditLogRepository.deleteByTimestampBefore(cutoff);
        log.info("Purged {} audit log entries older than {} days", deleted, retentionDays);
    }
}