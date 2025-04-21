package com.giftedlabs.eventoria.exception.events;

/**
 * Custom exception class for event validation errors.
 */
public class EventValidationException extends RuntimeException{

    public EventValidationException(String message) {
        super(message);
    }

    public EventValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
