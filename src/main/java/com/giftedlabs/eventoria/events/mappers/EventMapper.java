package com.giftedlabs.eventoria.events.mappers;

import com.giftedlabs.eventoria.events.domain.Address;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Geolocation;
import com.giftedlabs.eventoria.events.domain.Venue;
import com.giftedlabs.eventoria.events.dto.request.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.request.EventUpdateRequest;
import com.giftedlabs.eventoria.events.dto.request.VenueRequest;
import com.giftedlabs.eventoria.events.dto.response.*;
import org.springframework.stereotype.Component;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Objects;

/**
 * Mapper for converting between Event entities and DTO's
 */
@Component
public class EventMapper {

    /**
     * Create an EventCreateDTO to an Event entity
     *
     * @param createRequest The DTO to convert
     * @return The converted Event entity
     *
     */
    public Event toEntity(EventCreateRequestDTO createRequest) {
        if (createRequest == null) {
            return null;
        }

        return Event.builder()
                .name(createRequest.getName())
                .description(createRequest.getDescription())
                .venue(venueBuilder(createRequest.getVenue()))
                .category(createRequest.getCategory())
                .imageUrl(createRequest.getImageUrl())
                .startDate(createRequest.getStartDate())
                .endDate(createRequest.getEndDate())
                .isTicketed(createRequest.isTicketed())
                .participants(new ArrayList<>())
                .build();
    }

    /**
     * Code from the util class
     */

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("E, MMM d, yyyy");
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("h:mm a");

    /**
     * Convert create request DTO to entity
     */


    private static Address toAddressEntity(VenueRequest venueRequest){
        return Address.builder()
                .address(venueRequest.getAddress())
                .city(venueRequest.getCity())
                .state(venueRequest.getState())
                .country(venueRequest.getCountry())
                .zipCode(venueRequest.getZipCode())
                .geolocation(Geolocation.builder()
                        .latitude(venueRequest.getLatitude())
                        .longitude(venueRequest.getLongitude())
                        .build())
                .build();
    }



    private Venue venueBuilder(VenueRequest venueRequest){
        return Venue.builder()
                .venueName(venueRequest.getName())
                .address(toAddressEntity(venueRequest))
                .capacity(venueRequest.getCapacity())
                .isVirtual(venueRequest.isVirtual())
                .virtualMeetingUrl(venueRequest.getVirtualMeetingUrl())
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
            VenueRequest venueRequest = updateRequest.getVenue();

            Venue venue = event.getVenue();


            if (venue == null) {
                venue = new Venue();
                event.setVenue(venue);
            }

            if (venueRequest.getName() != null) {
                venue.setVenueName(venueRequest.getName());
            }

            if (venueRequest.getAddress() != null) {
                venue.setAddress(toAddressEntity(venueRequest));
            }

            if (venueRequest.getCapacity() != null) {
                venue.setCapacity(venueRequest.getCapacity());
            }

            venue.setVirtual(venueRequest.isVirtual());

            if (venueRequest.getVirtualMeetingUrl() != null) {
                venue.setVirtualMeetingUrl(venueRequest.getVirtualMeetingUrl());
            }

            if (venueRequest.getVirtualMeetingPassword() != null) {
                venue.setVirtualMeetingPassword(venueRequest.getVirtualMeetingPassword());
            }
        }
    }


    private static VenueResponse toVenueDTO(Event event){
        Venue venue = event.getVenue();
        return VenueResponse.builder()
                .name(venue.getVenueName())
                .address(venue.getAddress().getAddress())
                .city(venue.getAddress().getCity())
                .state(venue.getAddress().getState())
                .country(venue.getAddress().getCountry())
                .zipCode(venue.getAddress().getZipCode())
                .latitude(venue.getAddress().getGeolocation().getLatitude())
                .longitude(venue.getAddress().getGeolocation().getLongitude())
                .capacity(venue.getCapacity())
                .isVirtual(venue.isVirtual())
                .virtualMeetingUrl(venue.getVirtualMeetingUrl())
                .build();
    }

    private static OrganizerResponse toOrganizerDTO(Event event){
        return OrganizerResponse.builder()
                .id(event.getOrganizer().getId())
                .name(event.getOrganizer().getOrganizationName())
                .email(event.getOrganizer().getEmail())
                .phoneNumber(event.getOrganizer().getPhoneNumber())
                .logoUrl(event.getOrganizer().getLogoUrl())
                .build();
    }

    /**
     * Convert entity to response DTO
     */
    public EventResponse toResponse(Event event) {
        if (event == null) {
            return null;
        }

        VenueResponse venueResponse = toVenueDTO(event);

        OrganizerResponse organizerResponse = null;
        if (event.getOrganizer() != null) {
            organizerResponse =toOrganizerDTO(event);
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
            venueResponse = toVenueDTO(event);
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
                Objects.requireNonNull(event.getStartDate()).isAfter(LocalDateTime.now());

        boolean hasCapacityAvailable = true;
        assert event.getVenue() != null;
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
            venueResponse = toVenueDTO(event);
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
