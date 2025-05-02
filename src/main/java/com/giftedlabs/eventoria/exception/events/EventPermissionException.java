package com.giftedlabs.eventoria.exception.events;

/**
 * Exception thrown when user does not have permission to perform an operation on an event
 */
public class EventPermissionException extends RuntimeException {

    public EventPermissionException(String message) {
        super(message);
    }

    public EventPermissionException(String message, Throwable cause) {
        super(message, cause);
    }
}
