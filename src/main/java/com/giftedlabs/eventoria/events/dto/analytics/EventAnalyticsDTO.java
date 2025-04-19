package com.giftedlabs.eventoria.events.dto.analytics;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventAnalyticsDTO {

    private Long eventId;
    private int totalParticipants;
    private int attendedCount;
    private double attendanceRate;
    private Map<LocalDate, Integer> registrationsByDay;
    private int capacity;
    private double capacityUtilization;

    // Additional analytics can be added here as the application evolves;

    private Map<String, Integer> registrationsBySource;
    private Map<String, Double> conversionRates;
    private Map<String, Object> demographicData;
}
