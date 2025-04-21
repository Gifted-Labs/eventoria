package com.giftedlabs.eventoria.util;

import com.giftedlabs.eventoria.events.domain.Address;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Geolocation;
import com.giftedlabs.eventoria.events.domain.Venue;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequest;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.events.dto.response.*;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

@Component
public class EventMapperUtil {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("E, MMM d, yyyy");
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("h:mm a");

    /**
     * Convert create request DTO to entity
     */
    public Event toEntity(EventCreateRequest createRequest) {
        if (createRequest == null) {
            return null;
        }

        Address address = Address.builder()
                .address(createRequest.getVenue().getAddress())
                .city(createRequest.getVenue().getCity())
                .state(createRequest.getVenue().getState())
                .country(createRequest.getVenue().getCountry())
                .zipCode(createRequest.getVenue().getSipCode())
                .build();

        Geolocation geolocation = Geolocation.builder()
                .latitude(createRequest.getVenue().getLatitude())
                .longitude(createRequest.getVenue().getLongitude())
                .build();

        Venue venue = Venue.builder()

                .venueName(createRequest.getVenue().getName())
                .address(address)
                .geolocation(geolocation)
                .capacity(createRequest.getVenue().getCapacity())
                .isVirtual(createRequest.getVenue().isVirtual())
                .virtualMeetingUrl(createRequest.getVenue().getVirtualMeetingUrl())
                .virtualMeetingPassword(createRequest.getVenue().getVirtualMeetingPassword())
                .build();

        return Event.builder()
                .name(createRequest.getName())
                .description(createRequest.getDescription())
                .venue(venue)
                .category(createRequest.getCategory())
                .imageUrl(createRequest.getImageUrl())
                .startDate(createRequest.getStartDate())
                .endDate(createRequest.getEndDate())
                .isTicketed(createRequest.isTicketed())
                .participants(new ArrayList<>())
                .build();
    }

    /**
     * Update entity from update request DTO
     */
    public void updateEventFromDto(EventUpdateRequest updateRequest, Event event) {
        if (updateRequest == null) {
            return;
        }

        if (updateRequest.getName() != null) {
            event.setName(updateRequest.getName());
        }

        if (updateRequest.getDescription() != null) {
            event.setDescription(updateRequest.getDescription());
        }

        if (updateRequest.getCategory() != null) {
            event.setCategory(updateRequest.getCategory());
        }

        if (updateRequest.getImageUrl() != null) {
            event.setImageUrl(updateRequest.getImageUrl());
        }

        if (updateRequest.getStartDate() != null) {
            event.setStartDate(updateRequest.getStartDate());
        }

        if (updateRequest.getEndDate() != null) {
            event.setEndDate(updateRequest.getEndDate());
        }

        if (updateRequest.getIsTicketed() != null) {
            event.setTicketed(updateRequest.getIsTicketed());
        }

        // Update venue if provided
        if (updateRequest.getVenue() != null) {
            EventUpdateRequest.VenueRequest venueRequest = updateRequest.getVenue();


            // These codes needs to be optimized and removed
            Address address = Address.builder()
                    .address(venueRequest.getAddress())
                    .city(venueRequest.getCity())
                    .state(venueRequest.getCity())
                    .country(venueRequest.getCountry())
                    .zipCode(venueRequest.getZipCode())
                    .build();

            Geolocation geolocation = Geolocation.builder()
                    .latitude(venueRequest.getLatitude())
                    .longitude(venueRequest.getLongitude())
                    .build();

            Venue venue = event.getVenue();


            if (venue == null) {
                venue = new Venue();
                event.setVenue(venue);
            }

            if (venueRequest.getName() != null) {
                venue.setVenueName(venueRequest.getName());
            }

            if (venueRequest.getAddress() != null) {
                venue.setAddress(address);
            }

            if (venueRequest.getCapacity() != null) {
                venue.setCapacity(venueRequest.getCapacity());
            }

            if (venueRequest.getIsVirtual() != null) {
                venue.setVirtual(venueRequest.getIsVirtual());
            }

            if (venueRequest.getVirtualMeetingUrl() != null) {
                venue.setVirtualMeetingUrl(venueRequest.getVirtualMeetingUrl());
            }

            if (venueRequest.getVirtualMeetingPassword() != null) {
                venue.setVirtualMeetingPassword(venueRequest.getVirtualMeetingPassword());
            }
        }
    }

    /**
     * Convert entity to response DTO
     */
    public EventResponse toResponse(Event event) {
        if (event == null) {
            return null;
        }

        VenueResponse venueResponse = null;
        if (event.getVenue() != null) {

            Address address = event.getVenue().getAddress();
            Geolocation geolocation = event.getVenue().getGeolocation();
            venueResponse = VenueResponse.builder()
                    .name(event.getVenue().getVenueName())
                    .address(address.getAddress())
                    .city(address.getCity())
                    .state(address.getState())
                    .country(address.getCountry())
                    .zipCode(address.getZipCode())
                    .latitude(geolocation.getLatitude())
                    .longitude(geolocation.getLongitude())
                    .capacity(event.getVenue().getCapacity())
                    .isVirtual(event.getVenue().isVirtual())
                    .virtualMeetingUrl(event.getVenue().getVirtualMeetingUrl())
                    .build();
        }

        OrganizerResponse organizerResponse = null;
        if (event.getOrganizer() != null) {
            organizerResponse = OrganizerResponse.builder()
                    .id(event.getOrganizer().getId())
                    .name(event.getOrganizer().getOrganizationName())
                    .email(event.getOrganizer().getEmail())
                    .phoneNumber(event.getOrganizer().getPhoneNumber())
                    .logoUrl(event.getOrganizer().getLogoUrl())
                    .build();
        }

        return EventResponse.builder()
                .id(event.getId())
                .name(event.getName())
                .description(event.getDescription())
                .venue(venueResponse)
                .category(event.getCategory())
                .imageUrl(event.getImageUrl())
                .startDate(event.getStartDate().toLocalDate())
                .startTime(event.getStartDate().toLocalTime())
                .endDate(event.getEndDate().toLocalDate())
                .endTime(event.getEndDate().toLocalTime())
                .isTicketed(event.isTicketed())
                .isFeatured(event.isFeatured())
                .organizer(organizerResponse)
                .createdAt(event.getCreatedAt())
                .updatedAt(event.getUpdatedAt())
                .eventStatus(event.getEventStatus())
                .registrationCount(event.getParticipants().size())
                .build();
    }

    /**
     * Convert entity to detail response DTO
     */
    public EventDetailResponse toDetailResponse(Event event) {
        if (event == null) {
            return null;
        }

        VenueResponse venueResponse = null;
        if (event.getVenue() != null) {
            Address address = event.getVenue().getAddress();
            Geolocation geolocation = event.getVenue().getGeolocation();
            venueResponse = VenueResponse.builder()
                    .name(event.getVenue().getVenueName())
                    .address(address.getAddress() )
                    .city(address.getCity())
                    .state(address.getState())
                    .country(address.getCountry())
                    .zipCode(address.getZipCode())
                    .latitude(geolocation.getLatitude())
                    .longitude(geolocation.getLongitude())
                    .capacity(event.getVenue().getCapacity())
                    .isVirtual(event.getVenue().isVirtual())
                    .virtualMeetingUrl(event.getVenue().getVirtualMeetingUrl())
                    .build();
        }

        OrganizerResponse organizerResponse = null;
        if (event.getOrganizer() != null) {
            organizerResponse = OrganizerResponse.builder()
                    .id(event.getOrganizer().getId())
                    .name(event.getOrganizer().getOrganizationName())
                    .email(event.getOrganizer().getEmail())
                    .logoUrl(event.getOrganizer().getLogoUrl())
                    .phoneNumber(event.getOrganizer().getPhoneNumber())
//                    .upcomingEvents(new ArrayList<>()) // In a real implementation, we would populate this
                    .build();
        }

        String formattedStartDate = null;
        String formattedStartTime = null;
        String formattedEndDate = null;
        String formattedEndTime = null;

        if (event.getStartDate() != null) {
            formattedStartDate = event.getStartDate().format(DATE_FORMATTER);
            formattedStartTime = event.getStartDate().format(TIME_FORMATTER);
        }

        if (event.getEndDate() != null) {
            formattedEndDate = event.getEndDate().format(DATE_FORMATTER);
            formattedEndTime = event.getEndDate().format(TIME_FORMATTER);
        }

        boolean isRegistrationOpen = event.getEventStatus().name().equals("PUBLISHED") &&
                event.getStartDate().isAfter(LocalDateTime.now());

        boolean hasCapacityAvailable = true;
        if (event.getVenue().getCapacity() != null && event.getVenue().getCapacity() > 0) {
            hasCapacityAvailable = event.getParticipants().size() < event.getVenue().getCapacity();
        }

        return EventDetailResponse.builder()
                .id(event.getId())
                .name(event.getName())
                .description(event.getDescription())
                .venue(venueResponse)
                .category(event.getCategory())
                .imageUrl(event.getImageUrl())
                .startDate(event.getStartDate().toLocalDate())
                .startTime(event.getStartDate().toLocalTime())
                .endDate(event.getEndDate().toLocalDate())
                .endTime(event.getEndDate().toLocalTime())
                .isTicketed(event.isTicketed())
                .isFeatured(event.isFeatured())
                .organizer(organizerResponse)
                .createdAt(event.getCreatedAt())
                .updatedAt(event.getUpdatedAt())
                .eventStatus(event.getEventStatus())
                .registrationCount(event.getParticipants().size())
                .isRegistrationOpen(isRegistrationOpen)
//                .hasCapacityAvailable(hasCapacityAvailable)
                .build();
    }

    /**
     * Convert entity to summary response DTO
     */
    public EventSummaryResponse toSummaryResponse(Event event) {
        if (event == null) {
            return null;
        }

        VenueResponse venueResponse = null;

        if (event.getVenue() != null) {
            Address address = event.getVenue().getAddress();
            Geolocation geolocation = event.getVenue().getGeolocation();

            venueResponse = VenueResponse.builder()
                    .name(event.getVenue().getVenueName())
                    .address(address != null ? address.getAddress() : null)
                    .city(address != null ? address.getCity() : null)
                    .country(address != null ? address.getCountry() : null)
                    .latitude(geolocation != null ? geolocation.getLatitude() : null)
                    .longitude(geolocation != null ? geolocation.getLongitude() : null)
                    .capacity(event.getVenue().getCapacity())
                    .isVirtual(event.getVenue().isVirtual())
                    .build();
        }

        Long organizerId = null;
        String organizerName = null;

        if (event.getOrganizer() != null) {
            organizerId = event.getOrganizer().getId();
            organizerName = event.getOrganizer().getOrganizationName();
        }

        String formattedDate = null;
        String formattedTime = null;

        if (event.getStartDate() != null) {
            formattedDate = event.getStartDate().format(DATE_FORMATTER);
            formattedTime = event.getStartDate().format(TIME_FORMATTER);
        }

        // Truncate description for summary view
        String truncatedDescription = event.getDescription();
        if (truncatedDescription != null && truncatedDescription.length() > 150) {
            truncatedDescription = truncatedDescription.substring(0, 147) + "...";
        }

        return EventSummaryResponse.builder()
                .id(event.getId())
                .name(event.getName())
                .description(truncatedDescription)
                .imageUrl(event.getImageUrl())
                .startDate(event.getStartDate().toLocalDate())
                .startTime(event.getStartDate().toLocalTime())
                .category(event.getCategory())
                .eventStatus(event.getEventStatus())
                .isFeatured(event.isFeatured())
                .isTicketed(event.isTicketed())
                .venue(venueResponse)
                .organizerId(organizerId)
                .organizerName(organizerName)
                .registrationCount(event.getParticipants().size())
                .build();
    }
}
