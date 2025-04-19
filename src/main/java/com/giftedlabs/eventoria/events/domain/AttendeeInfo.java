package com.giftedlabs.eventoria.events.domain;

import jakarta.persistence.Embeddable;
import lombok.Data;

@Embeddable
@Data
public class AttendeeInfo {
    private String fullName;
    private String email;
    private String phoneNumber;
    private String city;
}
