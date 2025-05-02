package com.giftedlabs.eventoria.events.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DTO for attendance reports
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttendanceReportDTO {

    // Event identification
    private Long eventId;
    private String eventName;
    private Long organizerId;

    // Totals for organization-level reports
    private Integer totalEvents;

    // Registration stats
    private Integer totalRegistrations;
    private Integer checkedIn;
    private Integer cancelled;
    private Integer noShows;
    private Double attendanceRate;

    // Timelines
    private Map<LocalDateTime, Integer> registrationTimeline;
    private Map<LocalDateTime, Integer> checkInTimeline;

    // Event breakdown for organization-level reports
    private List<Map<String, Object>> eventBreakdown;

    // Time-based metrics
    private Integer earlyArrivals;
    private Integer lateArrivals;
    private Double averageArrivalTimeMinutes;

    // Demographic data (if available)
    private Map<String, Integer> attendeesByLocation;
}
