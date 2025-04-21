package com.giftedlabs.eventoria.events.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public  class OrganizerResponse {
    private Long id;
    private String name;
    private String email;
    private String phoneNumber;
    private String logoUrl;
}