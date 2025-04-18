package com.giftedlabs.eventoria.authentication.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignUpRequest(

        @NotBlank(message = "First name is required")
        @Size(min = 2, max = 255, message = "First name must be between 2 and 50 characters")
        String firstName,
        @NotBlank(message = "Last name is required")
        @Size(min = 2, max = 255, message = "Last name must be between 2 and 50 characters")
        String lastName,
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 30, message = "Username must be between 2 and 50 characters")
        String username,
        @NotBlank(message = "Email is required")
        @Email(message = "Please provide a valid email address")
        String email,
        @NotBlank(message = "Password is required")
        @Size(min = 8,  message = "Password must be between 8 and 255 characters")
        @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$",
                message = "Password must contain at least one digit, one lowercase, one uppercase letter, one special character, and no whitespace")
        String password,
        @NotBlank(message = "Phone number is required")
        @Size(min = 10, max = 15, message = "Phone number must be between 10 and 15 characters")
        @Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Phone number must be a valid format")
        String phoneNumber,
        String address,
        String city,
        String state,
        String country
) {




}
