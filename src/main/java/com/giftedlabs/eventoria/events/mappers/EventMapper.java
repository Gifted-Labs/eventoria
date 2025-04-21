package com.giftedlabs.eventoria.events.mappers;

import com.giftedlabs.eventoria.events.domain.Address;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Geolocation;
import com.giftedlabs.eventoria.events.domain.Venue;
import com.giftedlabs.eventoria.events.dto.EventCreateRequestDTO;
import com.giftedlabs.eventoria.events.dto.EventUpdateRequestDTO;
import org.springframework.stereotype.Component;

/**
 * Mapper for converting between Event entities and DTO's
 */
@Component
public class EventMapper {

    /**
     * Create an EventCreateDTO to an Event entity
     *
     * @param dto The DTO to convert
     * @return The converted Event entity
     *
     */
    public Event toEntity(EventCreateRequestDTO dto){
        if(dto == null){
            return null;
        }

        Event event = Event.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .startDate(dto.getStartDate())
                .endDate(dto.getEndDate())
                .category(dto.getCategory())
                .isTicketed(dto.isTicketed())
                .imageUrl(dto.getImageUrl())
                .build();

        if(dto.getVenue() != null){

            Address address = Address.builder()
                    .address(dto.getVenue().getAddress())
                    .city(dto.getVenue().getCity())
                    .state(dto.getVenue().getState())
                    .zipCode(dto.getVenue().getPostalCode())
                    .country(dto.getVenue().getCountry())
                    .build();

            Geolocation geolocation = Geolocation.builder()
                    .latitude(dto.getVenue().getLatitude())
                    .longitude(dto.getVenue().getLongitude())
                    .build();

            Venue venue = Venue.builder()
                    .venueName(dto.getVenue().getName())
                    .address(address)
                    .geolocation(geolocation)
                    .capacity(dto.getMaxAttendees())
                    .isVirtual(dto.getVenue().isVirtual())
                    .virtualMeetingUrl(dto.getVenue().getVirtualEventUrl())
                    .virtualMeetingPassword(dto.getVenue().getVirtualEventPassword())
                    .build();
            event.setVenue(venue);
        }

        // Additional properties
        event.setFeatured(dto.isFeatured());

        return event;
    }


    public void updateEventFromDTO(Event event, EventUpdateRequestDTO dto){
        if(dto == null || event == null){
            return;
        }

        // Update only non-null fields
        if (dto.getName() != null) {
            event.setName(dto.getName());
        }

        if (dto.getDescription() != null) {
            event.setDescription(dto.getDescription());
        }

        if (dto.getStartDate() != null) {
            event.setStartDate(dto.getStartDate());
        }

        if (dto.getEndDate() != null) {
            event.setEndDate(dto.getEndDate());
        }

        if (dto.getCategory() != null) {
            event.setCategory(dto.getCategory());
        }


        if (dto.getMaxAttendees() != null) {
            event.getVenue().setCapacity(dto.getMaxAttendees());
        }

        if (dto.getImageUrl() != null) {
            event.setImageUrl(dto.getImageUrl());
        }

        // Update venue if provided
        if (dto.getVenue() != null) {
            Venue venue = event.getVenue();
            if (venue == null) {
                venue = new Venue();
                event.setVenue(venue);
            }

            if (dto.getVenue().getName() != null) {
                venue.setVenueName(dto.getVenue().getName());
            }

            if (dto.getVenue().getAddress() != null) {
                venue.getAddress().setAddress(dto.getVenue().getAddress());
            }

            if (dto.getVenue().getCity() != null) {
                venue.getAddress().setCity(dto.getVenue().getCity());
            }

            if (dto.getVenue().getState() != null) {
                venue.getAddress().setState(dto.getVenue().getState());
            }

            if (dto.getVenue().getZipCode() != null) {
                venue.getAddress().setZipCode(dto.getVenue().getZipCode());
            }

            if (dto.getVenue().getCountry() != null) {
                venue.getAddress().setCountry(dto.getVenue().getCountry());
            }

            if (dto.getVenue().getCapacity() != null) {
                venue.setCapacity(dto.getVenue().getCapacity());
            }

            if (dto.getVenue().getLatitude() != null) {
                venue.getGeolocation().setLatitude(dto.getVenue().getLatitude());
            }

            if (dto.getVenue().getLongitude() != null) {
                venue.getGeolocation().setLongitude(dto.getVenue().getLongitude());
            }
        }

        // Additional properties
        if (dto.getFeatured() != null) {
            event.setFeatured(dto.getFeatured());
        }

    }
}
