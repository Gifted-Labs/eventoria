package com.giftedlabs.eventoria.config.application;

import org.apache.el.util.ConcurrentCache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

/**
 * Configuration for Caching
 */
@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Configure the cache manager
     * In prodcution environment, this would be replaced with a
     * more sophisticated cache manager like Redis or Hazelcast, Caffeine
     */
    @Bean
    public CacheManager cacheManager(){
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();


        // Configure Caches
        cacheManager.setCacheNames(Arrays.asList(
                "eventDetails",
                "eventSummaries",
                "upcomingEvents",
                "featuredEvents",
                "eventAnalytics",
                "organizerAnalytics",
                "userAnalytics",
                "platformAnalytics"
        ));

        return cacheManager;
    }

}
