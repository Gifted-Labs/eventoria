package com.giftedlabs.eventoria.events.dto;


import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for searching events.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventSearchRequestDTO {

    private String keyword;
    private List<Category> categories;
    private List<EventStatus> statuses;
    private LocalDateTime startDateFrom;
    private LocalDateTime startDateTo;
    private String city;
    private String state;
    private String country;
    private Double latitude;
    private Double longitude;
    private Double radiusInKm;
    private Boolean ticketedOnly;
    private Boolean freeOnly;
    private Double minPrice;
    private Double maxPrice;
    private Boolean featuredOnly;
    private Long organizerId;;
    private List<String> tags;
    private String sortBy;      // e.g "startDate", "endDate", "price", "popularity"
    private Integer page;
    private Integer size;
    private String sortDirection;       // Ascending or Descending
}
