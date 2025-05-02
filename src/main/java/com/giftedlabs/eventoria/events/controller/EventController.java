package com.giftedlabs.eventoria.events.controller;


import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.EventSearchRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.events.dto.request.PostponeEventRequest;
import com.giftedlabs.eventoria.events.dto.response.EventDetailResponse;
import com.giftedlabs.eventoria.events.dto.response.EventResponse;
import com.giftedlabs.eventoria.events.dto.response.EventSummaryResponse;
import com.giftedlabs.eventoria.events.mappers.EventMapper;
import com.giftedlabs.eventoria.events.service.EventService;
import com.giftedlabs.eventoria.utils.EventSecurityUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

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

    /**
     * Retrieves a paginated list of events.
     *
     * This endpoint allows clients to fetch a paginated list of all events.
     * The results can be customized by specifying the page number and the number of items per page.
     *
     * @param page The page number for the results, default is 0 (zero-based index).
     *             Example: `0` for the first page, `1` for the second page, etc.
     * @param size The number of items per page, default is 10.
     *             Example: `10` for 10 items per page.
     * @return A ResponseEntity containing a Page of EventDetailResponse objects.
     *         - HTTP 200: Successfully retrieved the list of events.
     *         - HTTP 401: Unauthorized - Authentication is required.
     *         - HTTP 403: Forbidden - Insufficient permissions.
     *         - HTTP 500: Internal Server Error - Unexpected server error.
     *
     * @apiNote This endpoint is accessible to all authenticated users.
     */
    @Operation(
            summary = "Retrieve a paginated list of events",
            description = "Fetches a paginated list of all events. Clients can specify the page number and size to customize the results.",
            tags = {"Events"},
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved the list of events",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = Page.class)
                            )
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized - Authentication is required",
                            content = @Content
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Forbidden - Insufficient permissions",
                            content = @Content
                    ),
                    @ApiResponse(
                            responseCode = "500",
                            description = "Internal Server Error - Unexpected server error",
                            content = @Content
                    )
            }
    )
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
     * Marks an event as completed.
     *
     * This endpoint allows an authenticated user with the role of "ROLE_ORGANIZER" or "ROLE_ADMIN"
     * to mark an event as completed. The event must exist, and the user must have the necessary
     * permissions to perform this action.
     *
     * @param eventId   The ID of the event to complete. This is a required path variable.
     * @param principal The authenticated user making the request. This is automatically provided
     *                  by the security context.
     * @return A ResponseEntity containing the details of the completed event in the response body.
     *         Returns HTTP 200 (OK) if the operation is successful.
     *
     * @apiNote This operation is restricted to users with the "ROLE_ORGANIZER" or "ROLE_ADMIN" roles.
     *          Ensure the event exists and the user has the appropriate permissions before calling this endpoint.
     */
    @Operation(
            summary = "Mark an event as completed",
            description = "Allows users with the roles 'ROLE_ORGANIZER' or 'ROLE_ADMIN' to mark an event as completed.",
            tags = {"Events"},
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Event successfully marked as completed",
                            content = @Content(schema = @Schema(implementation = EventResponse.class))
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Event not found",
                            content = @Content
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Forbidden - insufficient permissions",
                            content = @Content
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized - authentication required",
                            content = @Content
                    )
            }
    )
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


    /**
     * @apiNote Retrieves upcoming events that have not yet started
     * @return Paginated list of upcoming event summaries
     */
    @Operation(
            summary = "Get upcoming events",
            description = "Retrieves all events with start dates in the future, sorted and paginated according to the specified parameters",
            tags = {"Events"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successfully retrieved upcoming events",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Page.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - authentication required",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - insufficient permissions",
                    content = @Content
            )
    })
    @GetMapping("/upcoming")
    public ResponseEntity<Page<EventSummaryResponse>> getUpcomingEvents(
            @Parameter(description = "Page number (zero-based)", example = "0")
            @RequestParam(defaultValue = "0") int page,

            @Parameter(description = "Number of items per page", example = "10")
            @RequestParam(defaultValue = "10") int size,

            @Parameter(description = "Field to sort by", example = "startDate")
            @RequestParam(defaultValue = "startDate") String sortBy,

            @Parameter(description = "Sort direction ('asc' or 'desc')", example = "asc")
            @RequestParam(defaultValue = "asc") String direction) {

        Sort.Direction sortDirection = direction.equalsIgnoreCase("desc") ?
                Sort.Direction.DESC : Sort.Direction.ASC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortDirection, sortBy));

        Page<EventSummaryResponse> upcomingEvents = eventService.findUpcomingEvents(pageable);
        return ResponseEntity.ok(upcomingEvents);
    }


    /**
     * Searches events based on complex criteria provided in the request body.
     * Supports filtering by multiple parameters like keyword, category, location, price range, etc.
     * Results are paginated and can be sorted by specified fields.
     *
     * @param searchRequest The DTO containing all search parameters and criteria
     * @return A paginated response of events matching the search criteria
     */
    @PostMapping(value = "/search", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Search events with advanced criteria",
            description = "Search for events using multiple filters including keyword, category, " +
                    "date range, location, price range, and more. Results are paginated and sortable."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Events successfully retrieved",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Page.class))
            ),
            @ApiResponse(responseCode = "400", description = "Invalid search parameters provided"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<Page<Event>> searchEvents(
            @Parameter(description = "Search criteria and parameters", required = true)
            @Valid @RequestBody EventSearchRequestDTO searchRequest) {

        log.info("Received event search request: {}", searchRequest);

        try {
            // Apply default values if not specified
            if (searchRequest.getPage() == null) {
                searchRequest.setPage(0);
            }

            if (searchRequest.getSize() == null) {
                searchRequest.setSize(10);
            }

            // Create pageable object with sorting if provided
            Pageable pageable;
            if (searchRequest.getSortFields() != null && !searchRequest.getSortFields().isEmpty()) {
                List<Sort.Order> orders = new ArrayList<>();

                // Process each sort field
                for (EventSearchRequestDTO.SortField sortField : searchRequest.getSortFields()) {
                    Sort.Direction direction = "DESC".equalsIgnoreCase(sortField.getDirection())
                            ? Sort.Direction.DESC
                            : Sort.Direction.ASC;

                    orders.add(new Sort.Order(direction, sortField.getField()));
                }

                pageable = PageRequest.of(
                        searchRequest.getPage(),
                        searchRequest.getSize(),
                        Sort.by(orders)
                );
            } else {
                // Default sorting by start date if not specified
                pageable = PageRequest.of(
                        searchRequest.getPage(),
                        searchRequest.getSize(),
                        Sort.by(Sort.Direction.ASC, "startDate")
                );
            }

            // Execute search and return results
            Page<Event> events = eventService.searchEvents(searchRequest, pageable);

            log.info("Found {} events matching search criteria", events.getTotalElements());

            return ResponseEntity.ok(events);
        } catch (IllegalArgumentException e) {
            log.error("Invalid search parameters: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Error occurred while searching events", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}




