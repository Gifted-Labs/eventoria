package com.giftedlabs.eventoria.events.controller;


import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.response.EventDetailResponse;
import com.giftedlabs.eventoria.events.service.EventService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("api/events")
@RestController
public class EventController {


    private final EventService eventService;

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<EventDetailResponse> getEventById(@PathVariable Long id){
        log.info("REST request to get event by id: {}", id);
        EventDetailResponse eventDetailResponse = eventService.findEventById(id);
        return ResponseEntity.ok(eventDetailResponse);
    }

    @PostMapping("/create")
    public ResponseEntity<Event> createEvent(@Valid @RequestBody EventCreateRequestDTO createRequestDTO){
        log.info("REST request to create event: {}", createRequestDTO);
        Event eventDetailResponse = eventService.createEvent(createRequestDTO,6L);
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




}
