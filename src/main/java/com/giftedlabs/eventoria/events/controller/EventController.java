package com.giftedlabs.eventoria.events.controller;


import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.events.dto.request.PostponeEventRequest;
import com.giftedlabs.eventoria.events.dto.response.EventDetailResponse;
import com.giftedlabs.eventoria.events.dto.response.EventResponse;
import com.giftedlabs.eventoria.events.mappers.EventMapper;
import com.giftedlabs.eventoria.events.service.EventService;
import com.giftedlabs.eventoria.utils.EventSecurityUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("api/events")
@RestController
public class EventController {


    private final EventMapper eventMapper;
    private final EventService eventService;
    private final EventSecurityUtil securityUtil;


    @Operation(summary="Retrieve an event by ID", description = "Get an event object by specifying its id. The response includes full event details.\n")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Event found",
                    content = @Content(schema = @Schema(implementation = EventResponse.class))),
            @ApiResponse(
                    responseCode = "404",
                    description = "Event not found",
                    content = @Content),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized",
                    content = @Content)
    })
    @GetMapping("/{id}")
    public ResponseEntity<EventDetailResponse> getEventById(@PathVariable Long id) {
        log.info("REST request to get event by id: {}", id);
        EventDetailResponse eventDetailResponse = eventService.findEventById(id);
        return ResponseEntity.ok(eventDetailResponse);
    }

    @PostMapping("/create")
    public ResponseEntity<Event> createEvent(@Valid @RequestBody EventCreateRequestDTO createRequestDTO) {
        log.info("REST request to create event: {}", createRequestDTO);
        Event eventDetailResponse = eventService.createEvent(createRequestDTO, 6L);
        return ResponseEntity.ok(eventDetailResponse);
    }

    // Get all events pageable
    @GetMapping
    public ResponseEntity<Page<EventDetailResponse>> getAllEvents(@RequestParam(defaultValue = "0") int page,
                                                                  @RequestParam(defaultValue = "10") int size) {
        log.info("REST request to get all events");
        Page<EventDetailResponse> eventDetailResponse = eventService.getAllEvents(page, size);
        return ResponseEntity.ok(eventDetailResponse);
    }


    /**
     * Updates an existing event
     *
     * @param eventId            The ID of the event to update
     * @param eventUpdateRequest The update request containing the new event details
     * @param principal          The authenticated user
     * @return ResponseEntity containing the updated event
     */
    @PutMapping("/{eventId}")
    public ResponseEntity<EventResponse> updateEvent(
            @PathVariable Long eventId,
            @RequestBody @Valid EventUpdateRequest eventUpdateRequest,
            Principal principal) {

        // Extract organizer ID from authentication
        Long organizerId = securityUtil.getAuthenticatedUserId(principal);

        // Call service to update the event
        Event updatedEvent = eventService.updateEvent(eventId, eventUpdateRequest, organizerId);

        // Convert to response DTO
        EventResponse response = eventMapper.toResponse(updatedEvent);

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{eventId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Secured({"ROLE_ADMIN", "ROLE_ORGANIZER"})
    public void deleteEvent(
            @PathVariable Long eventId,
            Principal principal) {

        // Extract organizer ID from authentication context
        Long organizerId = securityUtil.getAuthenticatedUserId(principal);

        // Delegate to service (authorization already handled by @PreAuthorize)
        eventService.deleteEvent(eventId, organizerId);
    }

    /**
     * Publishes a draft event
     *
     * @param eventId   ID of the event to publish
     * @param principal Authenticated user
     * @return Published event details
     */
    @PostMapping("/{eventId}/publish")
    @Secured("ROLE_ORGANIZER")
    public ResponseEntity<EventResponse> publishEvent(
            @PathVariable Long eventId,
            Principal principal) {

        Long organizerId = securityUtil.getAuthenticatedUserId(principal);
        Event publishedEvent = eventService.publishEvent(eventId, organizerId);
        return ResponseEntity.ok(eventMapper.toResponse(publishedEvent));
    }

    /**
     * Cancels a published event
     *
     * @param eventId   ID of the event to cancel
     * @param principal Authenticated user
     * @return Cancelled event details
     */
    @PostMapping("/{eventId}/cancel")
    @Secured({"ROLE_ORGANIZER", "ROLE_ADMIN"})
    public ResponseEntity<EventResponse> cancelEvent(
            @PathVariable Long eventId,
            Principal principal) {

        Long organizerId = securityUtil.getAuthenticatedUserId(principal);
        Event cancelledEvent = eventService.cancelEvent(eventId, organizerId);
        return ResponseEntity.ok(eventMapper.toResponse(cancelledEvent));
    }

    /**
     * Postpones an event to a new date
     *
     * @param eventId   ID of the event to postpone
     * @param request   Contains new start date
     * @param principal Authenticated user
     * @return Postponed event details
     */
    @PostMapping("/{eventId}/postpone")
    @Secured({"ROLE_ORGANIZER", "ROLE_ADMIN"})
    public ResponseEntity<EventResponse> postponeEvent(
            @PathVariable Long eventId,
            @RequestBody @Valid PostponeEventRequest request,
            Principal principal) {

        Long organizerId = securityUtil.getAuthenticatedUserId(principal);
        Event postponedEvent = eventService.postponeEvent(
                eventId,
                request.getNewEventDate(),
                organizerId
        );
        return ResponseEntity.ok(eventMapper.toResponse(postponedEvent));
    }

    /**
     * Marks an event as completed
     *
     * @param eventId   ID of the event to complete
     * @param principal Authenticated user
     * @return Completed event details
     */
    @PostMapping("/{eventId}/complete")
    @Secured({"ROLE_ORGANIZER", "ROLE_ADMIN"})
    public ResponseEntity<EventResponse> completeEvent(
            @PathVariable Long eventId,
            Principal principal) {

        Long organizerId = securityUtil.getAuthenticatedUserId(principal);
        Event completedEvent = eventService.completeEvent(eventId, organizerId);
        return ResponseEntity.ok(eventMapper.toResponse(completedEvent));
    }

    /**
     * Archives a completed or cancelled event
     *
     * @param eventId   ID of the event to archive
     * @param principal Authenticated user
     * @return Archived event details
     */
    @PostMapping("/{eventId}/archive")
    @Secured({"ROLE_ORGANIZER", "ROLE_ADMIN"})
    public ResponseEntity<EventResponse> archiveEvent(
            @PathVariable Long eventId,
            Principal principal) {

        Long organizerId = securityUtil.getAuthenticatedUserId(principal);
        Event archivedEvent = eventService.archiveEvent(eventId, organizerId);
        return ResponseEntity.ok(eventMapper.toResponse(archivedEvent));
    }


}
