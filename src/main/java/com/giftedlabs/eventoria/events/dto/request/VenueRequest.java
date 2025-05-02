package com.giftedlabs.eventoria.events.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class  VenueRequest {

    @NotBlank(message = "Venue name is required")
    private String name;

    @NotBlank(message = "Venue address is required")
    private String address;

    @NotBlank(message = "City is required")
    private String city;

    private String state;

    @NotBlank(message = "Country is required")
    private String country;

    private String zipCode;

    private Double latitude;

    private Double longitude;

    private Integer capacity;

    private boolean isVirtual;

    private String virtualMeetingUrl;

    private String virtualMeetingPassword;
}
