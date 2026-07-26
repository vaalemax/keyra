package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.service.RateLimitService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ScheduledTasks {

    private final RateLimitService rateLimitService;

    private static final Logger log = LoggerFactory.getLogger(ScheduledTasks.class);

    public ScheduledTasks(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void clearRateLimitCache() {
        log.info("Starting scheduled rate limit cache cleanup");
        int sizeBefore = rateLimitService.getCacheSize();
        rateLimitService.clearCache();
        log.info("Rate limit cache cleared - removed {} entries", sizeBefore);
    }
}