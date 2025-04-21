package com.giftedlabs.eventoria.events.dto;

import com.giftedlabs.eventoria.enums.Category;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DTO for event creation requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventCreateRequestDTO {

    @NotBlank(message = "Event name is required")
    private String name;

    private String description;

    @NotNull(message = "Event start date is required")
    @Future(message = "Event start date must be in the future")
    private LocalDateTime startDate;

    @Future(message = "Event end date must be in the future")
    private LocalDateTime endDate;

    private Category category;

    private boolean ticketed;


    @PositiveOrZero(message = "Maximum attendees must be non-negative")
    private Integer maxAttendees;

    private String imageUrl;

    private String websiteUrl;

    @Valid
    private VenueDTO venue;

    private boolean featured;

    private boolean privateEvent;

    private List<String> tags;

    private Map<String, String> additionalProperties;
}