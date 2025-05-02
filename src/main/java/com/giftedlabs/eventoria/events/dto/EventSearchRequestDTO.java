package com.giftedlabs.eventoria.events.dto;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Enhanced DTO for advanced event searching.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventSearchRequestDTO {

    private String keyword;
    private List<Category> categories;
    private List<EventStatus> statuses;

    // Date filters
    private LocalDateTime startDateFrom;
    private LocalDateTime startDateTo;
    private LocalDateTime exactStartDate;
    private LocalDateTime exactEndDate;

    // Location filters
    private String city;
    private String state;
    private String country;
    private Double latitude;
    private Double longitude;
    private Double radiusInKm;

    // Price filters
    private Double minPrice;
    private Double maxPrice;

    // Capacity filters
    private Integer minCapacity;
    private Integer maxCapacity;

    // Tag filters
    private List<String> includeTags;
    private List<String> excludeTags;

    // Boolean filters
    private Boolean ticketedOnly;
    private Boolean freeOnly;
    private Boolean featuredOnly;
    private Boolean isVirtual;

    // Rating filters
//    private Double minRating;
//    private Double maxRating;
//    private Integer minReviews;

    // Event organizer
    private Long organizerId;

    // Sorting
    private List<SortField> sortFields; // Supports multi-field sorting

    // Pagination
    private Integer page = 0; // Default to page 0
    private Integer size = 10; // Default to 10 items per page

    // Search mode
    private String searchMode = "AND"; // Default to "AND" for combining filters

    /**
     * Inner class for multi-field sorting.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class SortField {
        private String field; // e.g., "startDate", "price"
        private String direction; // "ASC" or "DESC"
    }
}