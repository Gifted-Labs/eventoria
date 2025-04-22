package com.giftedlabs.eventoria.events.domain;

import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Address {

    private String address;
    private String city;
    private String state;
    private String country;
    private String zipCode;

    /**
     * The geolocation (latitude and longitude) of the venue encapsulated as an embeddable
     * {@code Geolocation} object. This field can be used for mapping or location-based searches.
     */
    @Embedded
    private Geolocation geolocation;
}
