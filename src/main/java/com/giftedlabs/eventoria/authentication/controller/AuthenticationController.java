package com.giftedlabs.eventoria.authentication.controller;

import com.giftedlabs.eventoria.authentication.dto.*;
import com.giftedlabs.eventoria.authentication.service.impl.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> registerUser(
            @Valid @RequestBody SignUpRequest registerRequest
    ) {
        MessageResponse messageResponse = authenticationService.registerUser(registerRequest);
        return ResponseEntity.ok(messageResponse);
    }


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody SignInRequest signInRequest) {
        JwtResponse jwtResponse = authenticationService.authenticateUser(signInRequest);
        return ResponseEntity.ok(jwtResponse);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<MessageResponse> verifyEmail(@RequestParam("token") String token) {
        MessageResponse messageResponse = authenticationService.verifyAccount(token);
        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(@RequestParam("email") String email) {
        MessageResponse messageResponse = authenticationService.requestPasswordReset(email);
        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody PasswordResetRequest passwordResetRequest
    ) {
        MessageResponse messageResponse = authenticationService.resetPassword(passwordResetRequest);
        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refreshToken(
            @RequestParam String refreshTokenRequest
    ) {
        JwtResponse jwtResponse = authenticationService.refreshToken(refreshTokenRequest);
        return ResponseEntity.ok(jwtResponse);
    }
}
