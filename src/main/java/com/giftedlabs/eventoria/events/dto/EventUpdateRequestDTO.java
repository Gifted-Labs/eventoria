package com.giftedlabs.eventoria.events.dto;


import com.giftedlabs.eventoria.enums.Category;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DTO for event update requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventUpdateRequestDTO {

    private String name;

    private String description;

    @Future(message = "Event start date must be in the future")
    private LocalDateTime startDate;

    @Future(message = "Event end date must be in the future")
    private LocalDateTime endDate;

    private Category category;

    private Boolean ticketed;

    @PositiveOrZero(message = "Ticket price must be non-negative")
    private Double ticketPrice;

    @PositiveOrZero(message = "Maximum attendees must be non-negative")
    private Integer maxAttendees;

    private String imageUrl;

    private String websiteUrl;

    @Valid
    private VenueDTO venue;

    private Boolean featured;

    private Boolean privateEvent;

    private List<String> tags;

    private Map<String, String> additionalProperties;
}