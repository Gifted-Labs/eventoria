package com.giftedlabs.eventoria.enums;

public enum EventState {
    PENDING, PUBLISHED, CANCELLED, EXPIRED, BLOCKED, DELETED


    // PENDING: The event is created but not yet published.
    // PUBLISHED: The event is live and visible to users.
    // CANCELLED: The event has been cancelled by the organizer.
    // EXPIRED: The event date has passed.
    // BLOCKED: The event is blocked due to some issues (e.g., policy violations).
    // DELETED: The event has been deleted by the organizer or admin.
    // Note: The actual implementation may vary based on the specific requirements of the application.
}
