package com.giftedlabs.eventoria.events.service;


import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.EventSearchRequestDTO;
import com.giftedlabs.eventoria.events.dto.EventUpdateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequest;
import com.giftedlabs.eventoria.events.dto.response.EventDetailResponse;
import com.giftedlabs.eventoria.events.dto.response.EventSummaryResponse;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 *  Event Service
 * @author Julius Adjetey Sowah
 */
public interface EventService {

    // CRUD Operations
    Event createEvent(EventCreateRequestDTO eventDTO, Long organizerId);

    Event updateEvent(Long eventId, EventUpdateRequestDTO eventDTO, Long organizerId);

    Event getEventById(Long eventId);

    Optional<Event> findEventById(Long eventId);

    void deleteEvent(Long eventId, Long organizerId);

    // Lifecycle Operations
    Event publishEvent(Long eventId, Long organizerId);

    Event cancelEvent(Long eventId, Long organizerId);

    Event postponeEvent(Long eventId, LocalDateTime newStartDate, Long organizerId);

    Event completeEvent(Long eventId, Long organizerId);

    Event archiveEvent(Long eventId, Long organizerId);

    // Batch Operations
    List<Event> batchUpdateEventStatus(List <Long> eventIds, EventStatus newStatus, Long organizerId);

    void batchDeleteEvents(List<Long> eventIds, Long organizerId);

    // Search and Filter Operations
    Page<Event> searchEvents(EventSearchRequestDTO searchRequest, Pageable pageable);

    Page<EventSummaryResponse> findEvents(
            String keyword,
            Category category,
            String city,
            LocalDateTime startDate,
            LocalDateTime endDate,
            List<EventStatus> status,
            Boolean isTicketed,
            Boolean isFeatured,
            Long organizerId,
            Pageable pageable
    );

    Page<Event> findEventsByOrganizer(Long organizerId, Pageable pageable);

    Page<Event> findEventsByCategory(Category category, Pageable pageable);

    Page<Event> findEventsByStatus(EventStatus status, Pageable pageable);

    Page<EventSummaryResponse> findFeaturedEvents(Pageable pageable);

    Page<EventSummaryResponse> findUpcomingEvents(Pageable pageable);

    Page<Event> findNearbyEvents(
            Double latitude,
            Double longitude,
            Double radiusInKm,
            Pageable pageable
    );

    // Administrative Operations
    Event setEventFeatured(Long eventId, Long organizerId);

    List<Event> generateEventReport(
            LocalDate startDate,
            LocalDate endDate,
            List<Category> categories,
            List<EventStatus> status,
            Pageable pageable
    );

    // Statistics and Analytics
    long countEventsByStatus(EventStatus status);

    long countEventsByCategory(Category category);

    long countEventsByOrganizer(Long organizerId);

    // Capacity Management
    boolean checkEvenCapacity (Long eventId);
    boolean getRemainingCapacity (Long eventId);

    // Export Operations
    byte[] exportEventsToCSV(List<Long> eventIds);
    byte[] exportEventsToExcel(List<Long> eventIds);

    // Ticket Management
    boolean checkTicketAvailability(Long eventId);

    // Recommendation System
    Page<Event> getRecommendedEvents(Long userId, Pageable pageable);

    // Registration Operations
    boolean registerUserForEvent(Long eventId, Long userId, String fullName, String phoneNumber, String email, String location);

    void canceelRegistration(Long eventId, Long userId);
}

