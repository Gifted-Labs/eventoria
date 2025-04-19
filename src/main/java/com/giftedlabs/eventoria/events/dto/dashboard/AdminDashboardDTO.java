package com.giftedlabs.eventoria.events.dto.dashboard;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Venue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * DTO for admin dashboard analytics data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminDashboardDTO {

    // Overall metrics
    private Integer totalEvents;
    private Integer totalUsers;
    private Integer activeEvents;
    private Integer totalOrganizers;
    private Integer totalAttendees;
    private Integer totalVenues;

    // Event metrics
    private Map<EventStatus, Integer> eventCountByStatus;
    private Map<Category, Integer> eventCountsByCategory;
    private Map<String, Integer> eventsByLocation;
    private Map<String, Integer> eventsByCity;
    private Map<String, Integer> eventsByDayOfWeek;
    private Map<String, Integer> virtualVsPhysicalCounts;

    // Revenue metrics
    private Integer totalTicketsSold;
    private Double totalRevenue;
    private Map<String, Double> revenueByMonth;
    private Map<Category, Double> revenueByCategory;
    private Double averageTicketPrice;
    private Map<String, Double> revenueByLocation;
    private Map<String, Double> revenueByCity;


    //User engagement metrics
    private Double averageEventsPerUser;
    private Double averageAttendanceRate;
    private Map<LocalDateTime, Integer> userEngagementByDay;
    private Map<LocalDateTime, Integer> registrationTrend;
    private Map<LocalDateTime, Integer> userGrowthTrend;

    // Top performers
    private Map<Long, Integer> topOrganizers;
    private Map<Long, Integer> topEvents;
    private Map<Category, Double> topCategories;
    private Map<Venue, Double> topVenues;

}
