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
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventDetailResponse {

    // General information
    private Long id;
    private String name;
    private String description;
    private LocalDate startDate;
    private LocalTime startTime;
    private LocalDate endDate;
    private LocalTime endTime;
    private VenueDTO venue;
    private String imageUrl;
    private Category category;
    private EventStatus status;
    private Boolean ticketed;
    private Boolean featured;
    private Long organizerId;
    private String organizerName;
    private String organizerEmail;
    private String organizerPhone;
    private String websiteUrl;
    private List<String> tags;
    private Boolean privateEvent;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Additional detailed information
    private Boolean isRegistrationOpen;
    private Integer remainingCapacity;
    private Double attendanceRate;
    private String eventAccessCode;
    private Boolean isVirtual;
    private String virtualEventUrl;
    private String cancellationPolicy;
    private List<Map<String, Object>> scheduleItems;
    private List<Map<String, Object>> speakers;
    private List<Map<String, Object>> sponsors;
    private Map<String, String> additionalProperties;
}
