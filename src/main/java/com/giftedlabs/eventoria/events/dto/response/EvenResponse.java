package com.giftedlabs.eventoria.events.dto.response;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EvenResponse {

    private Long id;
    private String name;
    private String description;
    private VenueResponse venue;
    private Category category;
    private imageUrl;
    private LocalDate startDate;
    private LocalTime startTime;
    private LocalDate endDate;
    private LocalTime endTime;
    private boolean isTicketed;
    private boolean isFeatured;
    private OrganizerResponse organizer;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private EventStatus eventStatus;
    private int registrationCount;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class VenueResponse {
        private String name;
        private String address;
        private String city;
        private String state;
        private String country;
        private String zipCode;
        private Double latitude;
        private Double longitude;
        private Integer capacity;
        private boolean isVirtual;
        private String virtualMeetingUrl;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class OrganizerResponse {
        private Long id;
        private String name;
        private String email;
        private String website;
    }
}
