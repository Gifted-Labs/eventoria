package com.giftedlabs.eventoria.utils;

import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.exception.events.EventValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Utility class for validating event-related data.
 */
@Component
@Slf4j
public class EventValidationUtil {

    /**
     * Validate event creation request
     *
     * @param eventDTO the event creation request DTO
     * @throws EventValidationException if validation fails
     */

    public void validateEventCreations(EventCreateRequestDTO eventDTO){
        log.debug("Validation event creation request");

        // Check required fields
        if(eventDTO.getName() == null || eventDTO.getName().isBlank()) {
            throw new EventValidationException("Event name is required");
        }

        if (eventDTO.getStartDate() == null || eventDTO.getEndDate() == null) {
            throw new EventValidationException("Event start and end dates are required");
        }

        // Check that start date is in the future
        if(eventDTO.getStartDate().isBefore(LocalDateTime.now())){
            throw new EventValidationException("Event start date must be in the future");
        }

        // Check that end date is after start date if provided
        if(eventDTO.getEndDate() != null && eventDTO.getEndDate().isBefore(eventDTO.getStartDate())){
            throw new EventValidationException("Event end date must be after start date");
        }

        // Check that ticket price is non-negative
//        if(eventDTO.isTicketed() && eventDTO.getTicketPrice() < 0){
//            throw new EventValidationException("Ticket price must be non-negative");
//        }

        // Validate venue capacity if provided
        if(eventDTO.getVenue() != null && eventDTO.getVenue().getCapacity() != null){
            if(eventDTO.getVenue().getCapacity() <= 0){
                throw new EventValidationException("Venue capacity must be positive");
            }
        }

        log.debug("Event creation request validation request successful");
    }


    /**
     * Validate event update request
     *
     * @param existingEvent The existing event
     * @param eventDTO The update request
     * @throws EventValidationException if validation fails
     */
    public void validateEventUpdate(Event existingEvent, EventUpdateRequest eventDTO) {
        log.debug("Validating event update request for event {}", existingEvent.getId());

        // Check that the event is not in a state that prevents updates
        if (existingEvent.getEventStatus() == EventStatus.CANCELLED ||
                existingEvent.getEventStatus() == EventStatus.COMPLETED ||
                existingEvent.getEventStatus() == EventStatus.ARCHIVED) {
            throw new EventValidationException("Cannot update an event in state: " + existingEvent.getEventStatus());
        }

        // Check that start date is in the future if changing
        if (eventDTO.getStartDate() != null && eventDTO.getStartDate().isBefore(LocalDateTime.now())) {
            throw new EventValidationException("Event start date must be in the future");
        }

        // Check that end date is after start date if both are provided
        if (eventDTO.getStartDate() != null && eventDTO.getEndDate() != null &&
                eventDTO.getEndDate().isBefore(eventDTO.getStartDate())) {
            throw new EventValidationException("Event end date must be after start date");
        }

        // Check that end date is after start date if only end date is being updated
        if (eventDTO.getStartDate() == null && eventDTO.getEndDate() != null &&
                eventDTO.getEndDate().isBefore(existingEvent.getStartDate())) {
            throw new EventValidationException("Event end date must be after start date");
        }

        // Check ticket price if updating for a ticketed event

        /**
         * if ((existingEvent.isTicketed() || Boolean.TRUE.equals(eventDTO.getIsTicketed())) &&
                eventDTO.getTicketPrice() != null && eventDTO.getTicketPrice() < 0) {
            throw new EventValidationException("Ticket price must be non-negative");
        }
        */


        // Validate venue capacity if updating
        if (eventDTO.getVenue() != null && eventDTO.getVenue().getCapacity() != null &&
                eventDTO.getVenue().getCapacity() <= 0) {
            throw new EventValidationException("Venue capacity must be greater than zero");
        }

        // Check that we're not reducing capacity below current registrations

        log.debug("Event update request validation passed for event {}", existingEvent.getId());
    }

    /**
     * Validate event publishing
     *
     * @param event The event to publish
     * @throws EventValidationException if validation fails
     */
    public void validateEventPublish(Event event) {
        log.debug("Validating event publishing for event {}", event.getId());

        // Check that the event is in a state that allows publishing
        if (event.getEventStatus() != EventStatus.DRAFT && event.getEventStatus() != EventStatus.POSTPONED) {
            throw new EventValidationException("Cannot publish an event in state: " + event.getEventStatus());
        }

        // Check that the event has required fields
        if (event.getName() == null || event.getName().isBlank()) {
            throw new EventValidationException("Event name is required for publishing");
        }

        if (event.getStartDate() == null) {
            throw new EventValidationException("Event start date is required for publishing");
        }

        // Check that start date is in the future
        if (event.getStartDate().isBefore(LocalDateTime.now())) {
            throw new EventValidationException("Event start date must be in the future for publishing");
        }

        // Check ticket price if the event is ticketed
//        if (event.isTicketed() && (event.getTicketPrice() == null || event.getTicketPrice() < 0)) {
//            throw new EventValidationException("Valid ticket price is required for ticketed events");
//        }

        log.debug("Event publishing validation passed for event {}", event.getId());
    }

    /**
     * Validate event cancellation
     *
     * @param event The event to cancel
     * @throws EventValidationException if validation fails
     */
    public void validateEventCancellation(Event event) {
        log.debug("Validating event cancellation for event {}", event.getId());

        // Check that the event is in a state that allows cancellation
        if (event.getEventStatus() == EventStatus.CANCELLED ||
                event.getEventStatus() == EventStatus.COMPLETED ||
                event.getEventStatus() == EventStatus.ARCHIVED) {
            throw new EventValidationException("Cannot cancel an event in state: " + event.getEventStatus());
        }

        log.debug("Event cancellation validation passed for event {}", event.getId());
    }

    /**
     * Validate event postponement
     *
     * @param event The event to postpone
     * @param newStartDate The new start date
     * @throws EventValidationException if validation fails
     */
    public void validateEventPostponement(Event event, LocalDateTime newStartDate) {
        log.debug("Validating event postponement for event {}", event.getId());

        // Check that the event is in a state that allows postponement
        if (event.getEventStatus() == EventStatus.CANCELLED ||
                event.getEventStatus() == EventStatus.COMPLETED ||
                event.getEventStatus() == EventStatus.ARCHIVED) {
            throw new EventValidationException("Cannot postpone an event in state: " + event.getEventStatus());
        }

        // Check that the new start date is valid
        if (newStartDate == null) {
            throw new EventValidationException("New start date is required for postponement");
        }

        // Check that new start date is in the future
        if (newStartDate.isBefore(LocalDateTime.now())) {
            throw new EventValidationException("New start date must be in the future");
        }

        // Check that new start date is different from current start date
        if (newStartDate.equals(event.getStartDate())) {
            throw new EventValidationException("New start date must be different from current start date");
        }

        log.debug("Event postponement validation passed for event {}", event.getId());
    }

    /**
     * Validate event completion
     *
     * @param event The event to mark as completed
     * @throws EventValidationException if validation fails
     */
    public void validateEventCompletion(Event event) {
        log.debug("Validating event completion for event {}", event.getId());

        // Check that the event is in a state that allows completion
        if (event.getEventStatus() != EventStatus.PUBLISHED && event.getEventStatus() != EventStatus.POSTPONED) {
            throw new EventValidationException("Cannot complete an event in state: " + event.getEventStatus());
        }

        // Check that the event has already occurred
        if (event.getEndDate() != null) {
            // If there's an end date, the event should have ended
            if (event.getEndDate().isAfter(LocalDateTime.now())) {
                throw new EventValidationException("Cannot mark an event as completed before its end date");
            }
        } else {
            // If there's no end date, the start date should be in the past
            if (event.getStartDate().isAfter(LocalDateTime.now())) {
                throw new EventValidationException("Cannot mark an event as completed before its start date");
            }
        }

        log.debug("Event completion validation passed for event {}", event.getId());
    }

    /**
     * Validate event archiving
     *
     * @param event The event to archive
     * @throws EventValidationException if validation fails
     */
    public void validateEventArchiving(Event event) {
        log.debug("Validating event archiving for event {}", event.getId());

        // Check that the event is in a state that allows archiving
        if (event.getEventStatus() != EventStatus.COMPLETED && event.getEventStatus() != EventStatus.CANCELLED) {
            throw new EventValidationException("Cannot archive an event in state: " + event.getEventStatus());
        }

        log.debug("Event archiving validation passed for event {}", event.getId());
    }

    /**
     * Check if registration is allowed for an event
     *
     * @param event The event
     * @throws EventValidationException if registration is not allowed
     */
    public void validateRegistrationAllowed(Event event) {
        log.debug("Validating if registration is allowed for event {}", event.getId());

        // Check that the event is published
        if (event.getEventStatus() != EventStatus.PUBLISHED && event.getEventStatus() != EventStatus.POSTPONED) {
            throw new EventValidationException("Cannot register for an event in state: " + event.getEventStatus());
        }

        // Check that the event hasn't already occurred
        if (event.getStartDate().isBefore(LocalDateTime.now())) {
            throw new EventValidationException("Cannot register for an event that has already started");
        }

        // Check that the event hasn't reached its capacity
//        if (event.getMaxAttendees() != null && event.getParticipants().size() >= event.getMaxAttendees()) {
//            throw new EventValidationException("Event has reached maximum capacity");
//        }

        log.debug("Registration validation passed for event {}", event.getId());
    }

    /**
     * Check if an event can be published
     *
     * @param event The event
     * @return True if the event can be published
     */
    public boolean canPublish(Event event) {
        try {
            validateEventPublish(event);
            return true;
        } catch (EventValidationException e) {
            log.debug("Event cannot be published: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if an event can be cancelled
     *
     * @param event The event
     * @return True if the event can be cancelled
     */
    public boolean canCancel(Event event) {
        try {
            validateEventCancellation(event);
            return true;
        } catch (EventValidationException e) {
            log.debug("Event cannot be cancelled: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if an event can be completed
     *
     * @param event The event
     * @return True if the event can be marked as completed
     */
    public boolean canComplete(Event event) {
        try {
            validateEventCompletion(event);
            return true;
        } catch (EventValidationException e) {
            log.debug("Event cannot be completed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if an event can be archived
     *
     * @param event The event
     * @return True if the event can be archived
     */
    public boolean canArchive(Event event) {
        try {
            validateEventArchiving(event);
            return true;
        } catch (EventValidationException e) {
            log.debug("Event cannot be archived: {}", e.getMessage());
            return false;
        }
    }

}
