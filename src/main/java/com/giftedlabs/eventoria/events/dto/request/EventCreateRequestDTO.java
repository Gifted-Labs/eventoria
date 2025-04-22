package com.giftedlabs.eventoria.events.dto.request;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventCreateRequestDTO {

    @NotBlank(message = "Event name is required")
    @Size(max = 255, message ="Event name cannot exceed 255 characters")
    private String name;

    @Size(max = 5000, message = "Event description cannot exceed 5000 characteds")
    private String description;

    private Category category;

    private EventStatus eventStatus = EventStatus.DRAFT;

    @Valid
    @NotNull(message = "Venue information is required")
    private VenueRequest venue;

    @Size(max = 512, message = "Image URL cannot exceed 512 characters")
    private String imageUrl;

    @NotNull(message = "Event start date is required")
    @Future(message = "Event start date must be in the future")
    private LocalDateTime startDate;

    private LocalDateTime endDate;

    private boolean isTicketed;

}
