package com.giftedlabs.eventoria.events.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VenueResponse {
    private String name;
    private String address;
    private String city;
    private String state;
    private String country;
    private String zipCode;
    private Double latitude;
    private Double longitude;
    private Integer capacity;
    private boolean isVirtual;
    private String virtualMeetingUrl;
}