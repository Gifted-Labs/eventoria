package com.giftedlabs.eventoria.events.dto.response;


import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.dto.VenueDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

/**
 * DTO for summarized event information in API responses
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventSummaryResponse {

    private Long id;
    private String name;
    private String description;
    private LocalDate startDate;
    private LocalTime startTime;
    private LocalDate endDate;
    private LocalTime endTime;
    private Category category;
    private EventStatus eventStatus;
    private Boolean ticketed;
    private Integer maxAttendees;
    private Integer currentAttendees;
    private Boolean featured;
    private String imageUrl;
    private VenueDTO venue;
    private String organizerName;
    private Long organizerId;
    private List<String> tags;
    private Boolean privateEvent;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}