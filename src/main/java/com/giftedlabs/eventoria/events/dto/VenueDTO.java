package com.giftedlabs.eventoria.events.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VenueDTO {

    private Long id;
    private String name;
    private String address;
    private String city;
    private String state;
    private String country;
    private String postalCode;
    private Double latitude;
    private Double longitude;
    private Integer capacity;
    private String zipCode;
    private String venueType;
    private String contactPhone;
    private String contactEmail;
    private String websiteUrl;
    private String accessibilityFeatures;
    private String parkingInfo;
    private String directions;
    private String imageUrl;
    private boolean isVirtual;
    private String virtualEventUrl;
    private String virtualEventPassword;

}
