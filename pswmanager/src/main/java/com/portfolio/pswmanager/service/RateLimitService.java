package com.portfolio.pswmanager.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class RateLimitService {

    private final Map<String, CopyOnWriteArrayList<Long>> requestTimestamps = new ConcurrentHashMap<>();

    private static final int NORMAL_LIMIT = 10;  // requests per minute
    private static final int STRICT_LIMIT = 5;   // requests per minute
    private static final long WINDOW_MS = 60_000; // 1 minute

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);

    public boolean isAllowed(String key) {
        return checkRateLimit(key, NORMAL_LIMIT);
    }

    public boolean isStrictAllowed(String key) {
        String strictKey = "strict:" + key;
        return checkRateLimit(strictKey, STRICT_LIMIT);
    }

    public int getRemainingRequests(String key, boolean strict) {
        int maxRequests = strict ? STRICT_LIMIT : NORMAL_LIMIT;
        String effectiveKey = strict ? "strict:" + key : key;

        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;

        CopyOnWriteArrayList<Long> timestamps = requestTimestamps.get(effectiveKey);

        if (timestamps == null) {
            return maxRequests;
        }

        timestamps.removeIf(timestamp -> timestamp < windowStart);

        int currentCount = timestamps.size();

        return Math.max(0, maxRequests - currentCount);
    }

    public long getSecondsUntilReset(String key, boolean strict) {
        String effectiveKey = strict ? "strict:" + key : key;

        CopyOnWriteArrayList<Long> timestamps = requestTimestamps.get(effectiveKey);

        if (timestamps == null || timestamps.isEmpty()) {
            return 0;
        }

        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;
        timestamps.removeIf(timestamp -> timestamp < windowStart);

        if (timestamps.isEmpty()) {
            return 0;
        }

        long oldestTimestamp = timestamps.getFirst();
        long resetTime = oldestTimestamp + WINDOW_MS;

        return Math.max(0, (resetTime - now) / 1000);
    }

    public void clearCache() {
        log.info("Clearing rate limit cache - {} entries", requestTimestamps.size());
        requestTimestamps.clear();
    }

    public int getCacheSize() {
        return requestTimestamps.size();
    }

    private boolean checkRateLimit(String key, int maxRequests) {
        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;

        CopyOnWriteArrayList<Long> timestamps = requestTimestamps.computeIfAbsent(
                key,
                k -> new CopyOnWriteArrayList<>()
        );

        timestamps.removeIf(timestamp -> timestamp < windowStart);

        if (timestamps.size() >= maxRequests) {
            log.warn("Rate limit exceeded for key: {} - current: {}/{} - BLOCKED",
                    key, timestamps.size(), maxRequests);
            return false;
        }

        timestamps.add(now);

        log.debug("Request allowed for key: {} ({}/{})", key, timestamps.size(), maxRequests);
        return true;
    }
}