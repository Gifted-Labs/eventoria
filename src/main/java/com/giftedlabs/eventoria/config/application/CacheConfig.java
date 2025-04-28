package com.giftedlabs.eventoria.config.application;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Configuration for Caching with differentiated strategies per cache
 */
@Configuration
@EnableCaching
public class CacheConfig {

    // Cache names
    public static final String EVENTS_CACHE = "events";
    public static final String EVENT_DETAILS_CACHE = "eventDetails";
    public static final String EVENT_SUMMARIES_CACHE = "eventSummaries";
    public static final String UPCOMING_EVENTS_CACHE = "upcomingEvents";
    public static final String FEATURED_EVENTS_CACHE = "featuredEvents";
    public static final String EVENT_ANALYTICS_CACHE = "eventAnalytics";
    public static final String ORGANIZER_ANALYTICS_CACHE = "organizerAnalytics";
    public static final String USER_ANALYTICS_CACHE = "userAnalytics";
    public static final String PLATFORM_ANALYTICS_CACHE = "platformAnalytics";

    /**
     * Primary cache manager with differentiated strategies
     */
    @Bean
    @Primary
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();

        // Default configuration (used when no specific config exists)
        cacheManager.setCaffeine(defaultCaffeineConfig());

        // Custom configurations for specific caches
        cacheManager.registerCustomCache(EVENTS_CACHE,
                Caffeine.newBuilder()
                        .maximumSize(1000)
                        .expireAfterWrite(30, TimeUnit.MINUTES)
                        .recordStats()
                        .build());

        cacheManager.registerCustomCache(EVENT_DETAILS_CACHE,
                Caffeine.newBuilder()
                        .maximumSize(500)
                        .expireAfterWrite(1, TimeUnit.HOURS)
                        .recordStats()
                        .build());

        cacheManager.registerCustomCache(UPCOMING_EVENTS_CACHE,
                Caffeine.newBuilder()
                        .maximumSize(500)
                        .expireAfterWrite(15, TimeUnit.MINUTES)
                        .refreshAfterWrite(5, TimeUnit.MINUTES)
                        .recordStats()
                        .build());

        cacheManager.registerCustomCache(FEATURED_EVENTS_CACHE,
                Caffeine.newBuilder()
                        .maximumSize(100)
                        .expireAfterWrite(1, TimeUnit.HOURS)
                        .recordStats()
                        .build());

        cacheManager.registerCustomCache(EVENT_ANALYTICS_CACHE,
                Caffeine.newBuilder()
                        .maximumSize(200)
                        .expireAfterWrite(2, TimeUnit.HOURS)
                        .recordStats()
                        .build());

        // Initialize all caches (including those with default config)
        cacheManager.setCacheNames(Arrays.asList(
                EVENTS_CACHE,
                EVENT_DETAILS_CACHE,
                EVENT_SUMMARIES_CACHE,
                UPCOMING_EVENTS_CACHE,
                FEATURED_EVENTS_CACHE,
                EVENT_ANALYTICS_CACHE,
                ORGANIZER_ANALYTICS_CACHE,
                USER_ANALYTICS_CACHE,
                PLATFORM_ANALYTICS_CACHE
        ));

        return cacheManager;
    }

    private Caffeine<Object, Object> defaultCaffeineConfig() {
        return Caffeine.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .recordStats();
    }


}