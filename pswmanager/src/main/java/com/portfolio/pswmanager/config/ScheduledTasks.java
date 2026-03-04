package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.service.RateLimitService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled tasks for maintenance operations.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ScheduledTasks {

    private final RateLimitService rateLimitService;

    /**
     * Clear rate limit cache every hour.
     */
    @Scheduled(cron = "0 0 * * * *")  // Every hour at :00
    public void clearRateLimitCache() {
        log.info("Starting scheduled rate limit cache cleanup");
        int sizeBefore = rateLimitService.getCacheSize();
        rateLimitService.clearCache();
        log.info("Rate limit cache cleared - removed {} entries", sizeBefore);
    }
}