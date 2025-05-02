package com.giftedlabs.eventoria.events.dto.request;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class PostponeEventRequest {

    @NotNull
    @Future(message = "New event date must be in the future")
    private LocalDateTime newEventDate;
}
