package com.giftedlabs.eventoria.events.repository;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface EventRepository extends JpaRepository<Event, Long> {

    Optional<Event> findEventByNameContainingIgnoreCase(String name);

    List<Event> findEventByOrganizerId(Long organizerId);

    Page<Event> findByOrganizerId(Long organizerId, Pageable pageable);

    Page<Event> findByIsFeaturedTrue(Pageable pageable);

    List<Event> findEventByIsFeaturedTrue();

    // Find by category
    Page<Event> findByCategory(Category category, Pageable pageable);

    List<Event> findEventByCategory(Category category);
    
    Page<Event> findByEventStatus(EventStatus eventStatus, Pageable pageable);

    List<Event> findEventByEventStatus(EventStatus eventStatus);

    List<Event> findByIsTicketedTrue();

    Page<Event> findEventByIsTicketedTrue(Pageable pageable);
    
    // Find Upcoming events
    @Query("SELECT e FROM Event e WHERE e.startDate > CURRENT_TIMESTAMP AND e.eventStatus = 'PUBLISHED' order by e.startDate ASC ")
    List<Event> findUpcomingEvents(Pageable pageable);

    // Advanced search queries
    Page<Event> findEventByNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(String name, String description, Pageable pageable);

    //Search Event
    @Query("SELECT e FROM Event e WHERE " +
            "(:name IS NULL OR LOWER(e.name) LIKE LOWER(CONCAT('%', :name, '%'))) AND " +
            "(:category IS NULL OR e.category = :category) AND " +
            "(:startDateFrom IS NULL OR e.startDate >= :startDateFrom) AND " +
            "(:startDateTo IS NULL OR e.startDate <= :startDateTo) AND " +
            "(:status IS NULL OR e.eventStatus = :status) AND " +
            "(:ticketed IS NULL OR e.isTicketed = :ticketed) AND " +
            "(:featured IS NULL OR e.isFeatured = :featured) AND " +
            "(e.organizer.id = :organizerId)")
    Page<Event> searchEvents(
            @Param("name") String name,
            @Param("category") Category category,
            @Param("startDateFrom")LocalDateTime startDateFrom,
            @Param("startDateTo") LocalDateTime startDateTo,
            @Param("status") EventStatus status,
            @Param("ticketed") Boolean ticketed,
            @Param("featured") Boolean featured,
            @Param("organizerId") Long organizerId,
            Pageable pageable);

    // Location-based queries
    @Query(value = """
    SELECT e FROM Event e
    WHERE 
        (6371000 * acos(
            cos(radians(:lat)) * cos(radians(e.venue.address.geolocation.latitude)) *
            cos(radians(e.venue.address.geolocation.longitude) - radians(:lng)) +
            sin(radians(:lat)) * sin(radians(e.venue.address.geolocation.latitude))
        )) <= :radiusInMeters
""")
    Page<Event> findEventsNearLocation(
            @Param("lat") Double latitude,
            @Param("long") Double longitude,
            @Param("radiusInMeters") Double radiusInMeters,
            Pageable pageable
    );


    // Find events by date range
    List<Event> findEventByStartDateBetween(LocalDateTime startDate, LocalDateTime endDate);

    Page<Event> findEventByStartDateBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);

    List<Event> findEventByStartDateBefore(@NotNull(message = "Event start time is required") LocalDateTime startDateBefore);

    Page<Event> findEventByStartDateBefore(@NotNull(message = "Event start time is required") LocalDateTime startDateBefore, Pageable pageable);

    List<Event> findEventByStartDateAfter(@NotNull(message = "Event start time is required") LocalDateTime startDateAfter);

    Page<Event> findEventByStartDateAfter(@NotNull(message = "Event start time is required") LocalDateTime startDateAfter, Pageable pageable);

    // Find events by date
    List<Event> findEventByStartDate(LocalDateTime startDate);

    Page<Event> findEventByStartDate(LocalDateTime startDate, Pageable pageable);

    // Analytics queries
    @Query("SELECT COUNT(e) FROM Event e WHERE e.eventStatus = :eventStatus")
    long countEventByEventStatus(@Param("status") EventStatus eventStatus);

    @Query("SELECT COUNT(e) FROM Event e WHERE e.organizer.id = :organizerId AND e.eventStatus = :eventStatus")
    long countEventByOrganizerAndEventStatus(@Param("organizerId") Long organizerId, @Param("eventStatus") EventStatus eventStatus);

    @Query("SELECT COUNT(e) FROM Event e WHERE e.category = :category")
    long countEventsByCategory(@Param("category") Category category);

    @Query("SELECT e.category, COUNT(e) FROM Event e GROUP BY e.category")
    List<Object[]> countEventsByCategory();

    // Query for recommendations( events similar to those the user has registered for
    @Query("SELECT e FROM Event e WHERE e.category IN " +
            "(SELECT e2.category FROM Event e2 JOIN e2.participants p WHERE p.user.id = :attendeeId) " +
            "AND e.id NOT IN (SELECT e3.id FROM Event e3 JOIN e3.participants p2 WHERE p2.user.id = :attendeeId) " +
            "AND e.eventStatus = 'PUBLISHED' AND e.startDate > :now")
    Page<Event> findRecommendedEventsForParticipant(
            @Param("participantId") Long participantId,
            @Param("now") LocalDateTime now,
            Pageable pageable);

    // Query for events with available capacity
    @Query("SELECT e FROM Event e WHERE e.venue.capacity > (SELECT COUNT(r) FROM participants r WHERE r.event.id = e.id) " +
            "AND e.eventStatus = 'PUBLISHED' AND e.startDate > :now")
    Page<Event> findEventsWithAvailableCapacity(
            @Param("now") LocalDateTime now,
            Pageable pageable);


    // Load Event with organizer details
    @Query("SELECT e FROM Event e JOIN FETCH e.organizer o WHERE e.id = :eventId")
    Optional<Event> findEventWithOrganizer(@Param("eventId") Long eventId);

    // Find events by multiple cateegories
    @Query("SELECT e FROM Event e WHERE e.category IN :categories AND e.eventStatus = 'PUBLISHED' AND e.startDate > :now")
    Page<Event> findEventByCategoryIn(
            @Param("categories") List<Category> categories,
            @Param("now") LocalDateTime now,
            Pageable pageable
    );

    /*
      @Query("SELECT new com.giftedlabs.eventoria.events.dto.EventAnalyticsDTO(" +
            "COUNT(e), " +
            "MIN(e.startDate), " +
            "MAX(e.startDate), " +
            "AVG(SIZE(e.participants)), " +
            "SUM(CASE WHEN e.isTicketed = true THEN 1 ELSE 0 END), " +
            "SUM(CASE WHEN e.isFeatured = true THEN 1 ELSE 0 END)) " +
            "FROM Event e WHERE e.organizer.id = :organizerId")
    EventAnalyticsDTO getEventAnalyticsForOrganizer(@Param("organizerId") Long organizerId);
     */
}



