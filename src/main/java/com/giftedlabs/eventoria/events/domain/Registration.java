package com.giftedlabs.eventoria.events.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.giftedlabs.eventoria.users.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity(name = "participants")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Registration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "event_id")
    @JsonManagedReference
    private Event event;

    // Affiliated user
    // Nullable if user is not registered
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    //Anonymous attendee info
    @Embedded
    private AttendeeInfo attendeeInfo;

    // List of all tickets purchased;
    // @OneToMany(mappedBy = "registration", cascade = CascadeType.ALL, orphanRemoval = true)
    // private List<Ticket> tickets = new ArrayList<>();

    private LocalDateTime createdAt;
}
