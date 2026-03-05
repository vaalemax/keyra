package com.portfolio.pswmanager.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Simple rate limiting service using sliding window algorithm.
 * No external dependencies required.
 */
@Slf4j
@Service
public class RateLimitService {

    // Store request timestamps per IP
    private final Map<String, CopyOnWriteArrayList<Long>> requestTimestamps = new ConcurrentHashMap<>();

    private static final int NORMAL_LIMIT = 10;  // requests per minute
    private static final int STRICT_LIMIT = 5;   // requests per minute
    private static final long WINDOW_MS = 60_000; // 1 minute

    /**
     * Check if request is allowed for normal rate limit (10 req/min).
     */
    public boolean isAllowed(String key) {
        return checkRateLimit(key, NORMAL_LIMIT);
    }

    /**
     * Check if request is allowed for strict rate limit (5 req/min).
     */
    public boolean isStrictAllowed(String key) {
        String strictKey = "strict:" + key;
        return checkRateLimit(strictKey, STRICT_LIMIT);
    }

    /**
     * Check rate limit using sliding window algorithm.
     */
    private boolean checkRateLimit(String key, int maxRequests) {
        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;

        // Get or create timestamp list for this key
        CopyOnWriteArrayList<Long> timestamps = requestTimestamps.computeIfAbsent(
                key,
                k -> new CopyOnWriteArrayList<>()
        );

        // Remove old timestamps outside the window
        timestamps.removeIf(timestamp -> timestamp < windowStart);

        // Check if limit exceeded
        if (timestamps.size() >= maxRequests) {
            log.warn("Rate limit exceeded for key: {} - current: {}/{} - BLOCKED",
                    key, timestamps.size(), maxRequests);
            return false;
        }

        // Add current timestamp
        timestamps.add(now);

        log.debug("Request allowed for key: {} ({}/{})", key, timestamps.size(), maxRequests);
        return true;
    }

    /**
     * Get remaining requests for a key.
     */
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

        // Count requests in current window
        int currentCount = timestamps.size();

        return Math.max(0, maxRequests - currentCount);
    }

    /**
     * Get seconds until rate limit resets.
     */
    public long getSecondsUntilReset(String key) {
        CopyOnWriteArrayList<Long> timestamps = requestTimestamps.get(key);

        if (timestamps == null || timestamps.isEmpty()) {
            return 0;
        }

        // Remove old timestamps first
        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;
        timestamps.removeIf(timestamp -> timestamp < windowStart);

        if (timestamps.isEmpty()) {
            return 0;
        }

        // Get the oldest timestamp
        long oldestTimestamp = timestamps.get(0);
        long resetTime = oldestTimestamp + WINDOW_MS;

        return Math.max(0, (resetTime - now) / 1000);
    }

    /**
     * Clear the cache.
     */
    public void clearCache() {
        log.info("Clearing rate limit cache - {} entries", requestTimestamps.size());
        requestTimestamps.clear();
    }

    /**
     * Get cache size.
     */
    public int getCacheSize() {
        return requestTimestamps.size();
    }
}