package com.giftedlabs.eventoria.events.service.impl;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.enums.UserRole;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.EventSearchRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.events.dto.response.EventDetailResponse;
import com.giftedlabs.eventoria.events.dto.response.EventSummaryResponse;
import com.giftedlabs.eventoria.events.mappers.EventMapper;
import com.giftedlabs.eventoria.events.repository.EventRepository;
import com.giftedlabs.eventoria.events.repository.specs.EventSpecification;
import com.giftedlabs.eventoria.events.service.EventService;
import com.giftedlabs.eventoria.exception.UserNotFoundException;
import com.giftedlabs.eventoria.exception.events.EventNotFoundException;
import com.giftedlabs.eventoria.exception.events.EventPermissionException;
import com.giftedlabs.eventoria.exception.events.EventValidationException;
import com.giftedlabs.eventoria.users.Organizer;
import com.giftedlabs.eventoria.users.User;
import com.giftedlabs.eventoria.users.UserRepository;
import com.giftedlabs.eventoria.utils.EventSecurityUtil;
import com.giftedlabs.eventoria.utils.EventValidationUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventServiceImpl implements EventService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final EventValidationUtil validationUtil;
    private final EventSecurityUtil securityUtil;
    private final UserRepository userRepository;

    // CRUD Operations

    @Override
    @Transactional
    public Event createEvent(EventCreateRequestDTO eventDTO, Long organizerId){
        log.info("Creating new event for organizer: {}", organizerId);

        // Validate the event data
        validationUtil.validateEventCreations(eventDTO);

        // Create event entity from DTO
        Event event = eventMapper.toEntity(eventDTO);

        // Set default values
        event.setEventStatus(EventStatus.DRAFT);
        event.setCreatedAt(LocalDateTime.now());
        event.setUpdatedAt(LocalDateTime.now());

        // Set organizer
        User organizer = userRepository.findById(organizerId).orElseThrow(
                () -> new UserNotFoundException("Cannot find user with ID: "+ organizerId)
        );
        // Check if user can create event
        if (!organizer.getRole().equals(UserRole.ROLE_ORGANIZER)) {
            throw new EventValidationException("You are not authorized to create event ");
        }
        event.setOrganizer((Organizer) organizer);

        // Save the event
        Event savedEvent = eventRepository.save(event);
        log.info("Event created successfully with ID: {}", savedEvent.getId());

        return savedEvent;




    }

    @Override
    @Transactional
    @CacheEvict(value = "events", key = "#id")
    public Event updateEvent(Long eventId, EventUpdateRequest eventDTO, Long organizerId) {
        log.info("Updating event ID: {} for organizer: {}", eventId, organizerId);

        // Find the event
        Event existingEvent = getEventById(eventId);

        // Check if the organizer is authorized to update the event
        if (securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to update this event");
        }

        // Validate update based on current event state.
        validationUtil.validateEventUpdate(existingEvent,eventDTO);

        // Update the event details from DTO
        eventMapper.updateEventFromDto(eventDTO,existingEvent);

        // Update timestamp
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save the updated event
        Event updatedEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} updated successfully", eventId);

        // Send notification to users who registered for the event
        // notificationService.sendEventUpdateNotification(updatedEvent);

        return updatedEvent;
    }


    @Override
    @Cacheable(value = "events", key = "#eventId", unless = "#result == null")
    public Event getEventById(Long eventId) {
        log.info("Fetching event with ID: {}", eventId);
        return eventRepository.findById(eventId)
                .orElseThrow(() -> new EventNotFoundException("Event not found with ID: " + eventId));
    }

    @Override
    public Page<EventDetailResponse> getAllEvents(int page, int size) {
        log.info("Fetching all events with page of {} and size {}",page,size );
        // Convert page and size into pageable
        Pageable pageable = Pageable.ofSize(size).withPage(page);
        // Fetch events from repository
        Page<Event> events = eventRepository.findAll(pageable);
        // Map events to DTOs
        return events.map(eventMapper::toDetailResponse);
    }

    @Cacheable(value = "events", key = "#root.args[0]", unless = "#result==null")
    public EventDetailResponse findEventById(Long eventId) {
        log.info("Finding event with ID: {}", eventId);
        return eventRepository.findById(eventId).map(eventMapper::toDetailResponse).orElseThrow(
                () -> new EventNotFoundException("Event not found with ID: " + eventId)
        );
    }

    @Override
    @Transactional
    @CacheEvict(value = "events", key = "#eventId")
    public void deleteEvent(Long eventId, Long organizerId) {
        log.info("Deleting event with ID: {} for organizer: {}", eventId, organizerId);

        // Find the event
        Event existingEvent = getEventById(eventId);

        // Check if organizer is authorized to delete the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to delete this event");
        }

        // Check if the event can be deleted based on it's status
        if (existingEvent.getEventStatus() == EventStatus.PUBLISHED &&
        existingEvent.getStartDate().isAfter(LocalDateTime.now())) {
            throw new EventPermissionException("Cannot delete a published event that has not occurred yet");
        }

        // Send notification to users who registered for the event
        // notificationService.sendEventCancellationNotification(event);

        //Delete the event
        eventRepository.delete(existingEvent);
        log.info("Event with ID: {} deleted successfully", eventId);
    }


    @Override
    @Transactional
    @CacheEvict(value = "events", key = "#eventId")
    public Event publishEvent(Long eventId, Long organizerId) {
        log.info("Publishing event ID: {} for organizer: {}", eventId, organizerId);

        // Find the event
        Event existingEvent = getEventById(eventId);

        // Check if organizer is authorized to publish the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to publish this event");
        }

        // Validate if the event can be published
        validationUtil.validateEventPublish(existingEvent);

        // Update the event
        existingEvent.setEventStatus(EventStatus.PUBLISHED);
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save the updated event
        Event publishedEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} published successfully", eventId);

        // Send notification
        // notificationService.sendEventPublishedNotification(existingEvent);

        return publishedEvent;
    }

    @Override
    @Transactional
    @CacheEvict(value = "events", key = "eventId")
    public Event cancelEvent(Long eventId, Long organizerId) {
        log.info("Cancelling event ID: {} for organizer: {}", eventId, organizerId);

        // Find the event
        Event existingEvent = getEventById(eventId);

        // Check if the organizer is authorized to cancel the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to cancel this event");
        }

        // Validate if event can be cancelled
        validationUtil.validateEventCancellation(existingEvent);

        // Update the event status
        existingEvent.setEventStatus(EventStatus.CANCELLED);
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save the updated Event
        Event cancelledEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} cancelled successfully", eventId);

        // Send notification to all registered participants
        // notificationService.sendEventCancellationNotification(existingEvent);

        return cancelledEvent;
    }

    @Override
    @Transactional
    @CacheEvict(value = "events", key = "#eventId")
    public Event postponeEvent(Long eventId, LocalDateTime newStartDate, Long organizerId) {
        log.info("Postponing event ID: {} for organizer: {}", eventId, organizerId);

        // Find event
        Event existingEvent = getEventById(eventId);

        // Check if organizer is authorized to postpone the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to postpone this event");
        }

        // Validate if event can be postponed
        validationUtil.validateEventPostponement(existingEvent, newStartDate);

        // Update the event dates and status
        existingEvent.setStartDate(newStartDate);
        if(existingEvent.getEndDate() != null) {
            // Maintain the same duration
            long durationHours = existingEvent.getEndDate().getHour() - existingEvent.getStartDate().getHour();
            existingEvent.setEndDate(newStartDate.plusHours(durationHours));
        }

        // Update the event status
        existingEvent.setEventStatus(EventStatus.POSTPONED);
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save the updated event
        Event postponedEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} postponed successfully", eventId);

        // Send notification to all registered participants
        // notificationService.sendEventPostponedNotification(existingEvent);

        return postponedEvent;
    }

    @Override
    @Transactional
    @CacheEvict(value = "events", key = "#eventId")
    public Event completeEvent(Long eventId, Long organizerId) {
        log.info("Marking event ID: {} as completed for organizer: {}", eventId, organizerId);

        // Find events
        Event existingEvent = getEventById(eventId);

        // Check if the organizer is authorized to complete the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to complete this event");
        }

        // Validate if the event can be marked as completed
        validationUtil.validateEventCompletion(existingEvent);

        // Update the event status
        existingEvent.setEventStatus(EventStatus.COMPLETED);
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save the updated event
        Event completedEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} marked as completed successfully", eventId);

        return completedEvent;
    }

    @Override
    public Event archiveEvent(Long eventId, Long organizerId) {
        log.info("Archiving event ID: {} for organizer: {}", eventId, organizerId);

        // Find the event
        Event existingEvent = getEventById(eventId);

        // Check if the organizer is authorized to archive the event
        if (!securityUtil.isEventOrganizer(existingEvent, organizerId)) {
            throw new EventPermissionException("Not authorized to archive this event");
        }

        // Validate if the event can be archived
        validationUtil.validateEventArchiving(existingEvent);

        //Update the event status
        existingEvent.setEventStatus(EventStatus.ARCHIVED);
        existingEvent.setUpdatedAt(LocalDateTime.now());

        // Save event
        Event archivedEvent = eventRepository.save(existingEvent);
        log.info("Event ID: {} archived successfully", eventId);

        return archivedEvent;
    }
    
    

    @Override
    public List<Event> batchUpdateEventStatus(List<Long> eventIds, EventStatus newStatus, Long organizerId) {
        return List.of();
    }

    @Override
    public void batchDeleteEvents(List<Long> eventIds, Long organizerId) {

    }

    @Override
    @Cacheable(value = "eventsSearch", key = "#searchRequest.hashCode().toString().concat('-').concat(#pageable.pageNumber.toString()).concat('-').concat(#pageable.pageSize.toString())", unless = "#result == null or #result.isEmpty()")
    public Page<Event> searchEvents(EventSearchRequestDTO searchRequest, Pageable pageable) {
        log.info("Searching events with criteria: {}", searchRequest);

        // Build the specification based on the search request
        Specification<Event> spec = EventSpecification.buildSpecification(
                searchRequest.getKeyword(),
                searchRequest.getCategories(),
                searchRequest.getStatuses(),
                searchRequest.getStartDateFrom(),
                searchRequest.getStartDateTo(),
                searchRequest.getExactStartDate(),
                searchRequest.getExactEndDate(),
                searchRequest.getTicketedOnly(),
                searchRequest.getFreeOnly(),
                searchRequest.getFeaturedOnly(),
                searchRequest.getOrganizerId(),
                searchRequest.getCity(),
                searchRequest.getState(),
                searchRequest.getCountry(),
                searchRequest.getLatitude(),
                searchRequest.getLongitude(),
                searchRequest.getRadiusInKm(),
                searchRequest.getMinPrice(),
                searchRequest.getMaxPrice(),
                searchRequest.getMinCapacity(),
                searchRequest.getMaxCapacity(),
                searchRequest.getIncludeTags(),
                searchRequest.getExcludeTags(),
//                searchRequest.getMinRating(),
//                searchRequest.getMaxRating(),
//                searchRequest.getMinReviews(),
                searchRequest.getIsVirtual()
        );
        return eventRepository.findAll(spec, pageable);
    }

    @Override
    public Page<EventSummaryResponse> findEvents(String keyword, Category category, String city, LocalDateTime startDate, LocalDateTime endDate, List<EventStatus> status, Boolean isTicketed, Boolean isFeatured, Long organizerId, Pageable pageable) {
        return null;
    }

    @Override
    public Page<Event> findEventsByOrganizer(Long organizerId, Pageable pageable) {
        Page<Event> events = eventRepository.findByOrganizerId(organizerId, pageable);
        if (events.isEmpty()) {
            throw new EventNotFoundException("No events found for organizer with ID: " + organizerId);
        }
        return events;
    }

    @Override
    public Page<Event> findEventsByCategory(Category category, Pageable pageable) {
        return eventRepository.findByCategory(category, pageable);
    }

    @Override
    public Page<Event> findEventsByStatus(EventStatus status, Pageable pageable) {
        return null;
    }

    @Override
    public Page<EventSummaryResponse> findFeaturedEvents(Pageable pageable) {
        Page<Event> featuredEvents = eventRepository.findByIsFeaturedTrue(pageable);
        return featuredEvents.map(eventMapper::toSummaryResponse);
    }

    @Override
    public Page<EventSummaryResponse> findUpcomingEvents(Pageable pageable) {
        Page<Event> upcomingEvents = eventRepository.findEventByStartDateAfter(LocalDateTime.now(), pageable);
        return upcomingEvents.map(eventMapper::toSummaryResponse);
    }

    @Override
    public Page<Event> findNearbyEvents(Double latitude, Double longitude, Double radiusInKm, Pageable pageable) {
        Page<Event> eventsNearby = eventRepository.findEventsNearLocation(latitude,longitude,radiusInKm,pageable);
        // Validate the radius value
        if (radiusInKm <= 0) {
            throw new EventValidationException("Invalid radius value: " + radiusInKm);
        }

        if(eventsNearby.isEmpty()) {
            throw new EventNotFoundException("No events found within the specified radius");
        }
        return eventsNearby;
    }

    @Override
    public Event setEventFeatured(Long eventId, Long userId) {
        Event existingEvent = eventRepository.findById(eventId).orElseThrow(
                () -> new EventNotFoundException("Event not found with ID: " + eventId)
        );

        // Get the User trying to perform the action
        User user = userRepository.findById(userId).orElseThrow(
                () -> new UserNotFoundException("User not found with ID: " + userId)
        );
        if(!securityUtil.isUserAdmin(user)){
            throw new EventPermissionException("User not authorized to set event as featured");
        }
        existingEvent.setFeatured(true);
        existingEvent.setUpdatedAt(LocalDateTime.now());
        return eventRepository.save(existingEvent);
    }

    @Override
    public List<Event> generateEventReport(LocalDate startDate, LocalDate endDate, List<Category> categories, List<EventStatus> status, Pageable pageable) {
        return List.of();
    }

    @Override
    public long countEventsByStatus(EventStatus status) {
        return 0;
    }

    @Override
    public long countEventsByCategory(Category category) {
        return 0;
    }

    @Override
    public long countEventsByOrganizer(Long organizerId) {
        return 0;
    }

    @Override
    public boolean checkEvenCapacity(Long eventId) {
        return false;
    }

    @Override
    public boolean getRemainingCapacity(Long eventId) {
        return false;
    }

    @Override
    public byte[] exportEventsToCSV(List<Long> eventIds) {
        return new byte[0];
    }

    @Override
    public byte[] exportEventsToExcel(List<Long> eventIds) {
        return new byte[0];
    }

    @Override
    public boolean checkTicketAvailability(Long eventId) {
        return false;
    }

    @Override
    public Page<Event> getRecommendedEvents(Long userId, Pageable pageable) {
        // Check if the user exists
        User user = userRepository.findById(userId).orElseThrow(
                () -> new UserNotFoundException("User not found with ID: " + userId)
        );
        return eventRepository.findRecommendedEventsForParticipant(userId,LocalDateTime.now(), pageable);
    }

    @Override
    public boolean registerUserForEvent(Long eventId, Long userId, String fullName, String phoneNumber, String email, String location) {
        return false;
    }

    @Override
    public void canceelRegistration(Long eventId, Long userId) {

    }


}
