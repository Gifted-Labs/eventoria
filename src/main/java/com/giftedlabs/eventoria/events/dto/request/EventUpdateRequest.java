package com.giftedlabs.eventoria.events.dto.request;

import com.giftedlabs.eventoria.enums.Category;
import jakarta.validation.Valid;
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
public class EventUpdateRequest {

    @Size(max = 255, message = "Event name cannot exceed 255 characters")
    private String name;

    @Size(max = 5000, message = "Event description cannot exceed 5000 characters")
    private String description;

    @Valid
    private VenueRequest venue;

    private Category category;

    @Size(max = 512, message = "Image URL cannot exceed 512 characters")
    private String imageUrl;

    private LocalDateTime startDate;

    private LocalDateTime endDate;

    private Boolean isTicketed;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class VenueRequest {
        private String name;
        private String address;
        private String city;
        private String state;
        private String country;
        private String zipCode;
        private Double latitude;
        private Double longitude;
        private Integer capacity;
        private Boolean isVirtual;
        private String virtualMeetingUrl;
        private String virtualMeetingPassword;
    }
}