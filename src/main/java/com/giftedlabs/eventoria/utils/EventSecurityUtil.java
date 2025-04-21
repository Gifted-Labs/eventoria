package com.giftedlabs.eventoria.utils;


import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Registration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * Utility class for event security operations
 */
@Component
@Slf4j
public class EventSecurityUtil {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();

    /**
     * Check if a user is the organizer of an event
     *
     * @param event The event
     * @param userId The user ID
     * @return True if the user is the organizer
     */
    public boolean isEventOrganizer(Event event, Long userId) {
        if (event == null || event.getOrganizer() == null || userId == null) {
            return false;
        }

        return userId.equals(event.getOrganizer().getId());
    }

    /**
     * Check if a user is a registered attendee for an event
     *
     * @param event The event
     * @param userId The user ID
     * @return True if the user is a registered attendee
     */
    public boolean isEventAttendee(Event event, Long userId) {
        if (event == null || userId == null) {
            return false;
        }

        return event.getParticipants().stream()
                .anyMatch(p -> Objects.equals(p.getEvent().getId(), event.getId()));
    }

    /**
     * Generate a unique ticket code for a registration
     *
     * @param event The event
     * @param attendeeId The attendee ID
     * @return A unique ticket code
     */
    public String generateTicketCode(Event event, Long attendeeId) {
        // Generate a random part
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        String randomPart = base64Encoder.encodeToString(randomBytes).substring(0, 8);

        // Combine event ID, attendee ID, and random part for uniqueness
        String ticketCode = "TCKT-" + event.getId() + "-" + attendeeId + "-" + randomPart;

        return ticketCode;
    }

    /**
     * Generate a check-in token for a registration
     * This token would typically be used for QR codes
     *
     * @param registration The registration
     * @return A check-in token
     */
    public String generateCheckInToken(Registration registration) {
        // Create a UUID for uniqueness
        String uuid = UUID.randomUUID().toString().replace("-", "");

        // Combine registration ID, event ID, and UUID for security
        String token = "CHKN-" + registration.getId() + "-" +
                registration.getEvent().getId() + "-" + uuid;

        return token;
    }

    /**
     * Validate a check-in token
     *
     * @param token The token to validate
     * @param registrationId The expected registration ID
     * @param eventId The expected event ID
     * @return True if the token is valid
     */
    public boolean validateCheckInToken(String token, Long registrationId, Long eventId) {
        if (token == null || !token.startsWith("CHKN-")) {
            return false;
        }

        String[] parts = token.split("-");
        if (parts.length < 4) {
            return false;
        }

        try {
            Long tokenRegistrationId = Long.parseLong(parts[1]);
            Long tokenEventId = Long.parseLong(parts[2]);

            return tokenRegistrationId.equals(registrationId) && tokenEventId.equals(eventId);
        } catch (NumberFormatException e) {
            log.warn("Invalid check-in token format: {}", token);
            return false;
        }
    }

    /**
     * Create an access code for private events
     *
     * @return A unique access code
     */
    public String generateEventAccessCode() {
        // Generate 6 random bytes
        byte[] randomBytes = new byte[6];
        secureRandom.nextBytes(randomBytes);

        // Convert to an alphanumeric string
        return base64Encoder.encodeToString(randomBytes)
                .replaceAll("[^A-Za-z0-9]", "")
                .substring(0, 8)
                .toUpperCase();
    }

    /**
     * Verify a ticket code is valid for an event
     *
     * @param event The event
     * @param ticketCode The ticket code to verify
     * @return True if the ticket code is valid
     */
    public Registration verifyTicketCode(Event event, String ticketCode) {
        if (event == null || ticketCode == null) {
            return null;
        }


        return null;
//        return event.getParticipants().stream()
//                .filter(p -> ticketCode.equals(p.getTicketCode()) &&
//                        p.getStatus() != Registration.RegistrationStatus.CANCELLED)
//                .findFirst()
//                .orElse(null);
    }

    /**
     * Hash sensitive data for logging
     *
     * @param data The data to hash
     * @return A hashed representation
     */
    public String hashForLogging(String data) {
        if (data == null) {
            return null;
        }

        // In a real implementation, this would use a proper hashing algorithm
        // For this example, we'll just use a simple obfuscation
        if (data.length() <= 4) {
            return "****";
        }

        return data.substring(0, 2) + "****" + data.substring(data.length() - 2);
    }

    /**
     * Generate an admin reset token with expiration
     *
     * @param adminId The admin ID
     * @param expirationMinutes Minutes until expiration
     * @return A reset token and expiration time
     */
    public String generateAdminActionToken(Long adminId, int expirationMinutes) {
        // Generate a random part
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String randomPart = base64Encoder.encodeToString(randomBytes);

        // Calculate expiration time
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(expirationMinutes);

        // Combine admin ID, expiration, and random part
        String tokenData = adminId + ":" + expiration.toString() + ":" + randomPart;

        // In a real implementation, this would be signed or encrypted
        return base64Encoder.encodeToString(tokenData.getBytes());
    }
}