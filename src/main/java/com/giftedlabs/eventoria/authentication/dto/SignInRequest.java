package com.giftedlabs.eventoria.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;


public record SignInRequest(
        @NotBlank(message = "Username or email is required")
        String usernameOrEmail,

        @NotBlank(message = "Password is required")
        String password
) {
}


