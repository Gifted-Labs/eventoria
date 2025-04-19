package com.giftedlabs.eventoria.events.dto.dashboard;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;


/**
 * DTO for organizer dashboard analytics data
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrganizerDashboardDTO {

    // Organizer Details
    private Long organizerId;
    private String organizerName;
    private Integer totalEvents;

    // Event Metrics
    private Map<EventStatus, Long> eventCountsByState;
    private Map<Category, Long> eventCountsByCategory;
    private Long registrationCount;
    private Long checkInCount;
    private Double attendanceRate;

    // Financial metrics
    private Double totalRevenue;
    private Double averageTicketPrice;
    private Map<String, Double> revenueByMonth;
    private Map<Category, Double> revenueByCategory;

    // Attendee metrics
    private Map<Long, Double> eventAttendanceRates;
    private Double averageAttendancePerEvent;
    private Map<LocalDateTime, Integer> registrationTrend;

    // Top performing events
    private Map<Long, Integer> topEvents;
    private Map<Long, Double> topRevenueEvents;
    private Category topCategory;





}
