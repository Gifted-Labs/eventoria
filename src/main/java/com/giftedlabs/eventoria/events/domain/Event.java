package com.giftedlabs.eventoria.events.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.users.Organizer;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "events")
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String description;

    @Embedded
    private Venue venue;

    @Enumerated(EnumType.STRING)
    private Category category;

    @Size(max = 512)
    private String imageUrl;

    @NotNull(message = "Event start time is required")
    private LocalDateTime startDate;

    @Column(nullable = true)
    private LocalDateTime endDate;

    private boolean isTicketed;

    private Integer rating;

    private boolean isFeatured;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organizer_id")
    @JsonBackReference
    private Organizer organizer;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Enumerated(EnumType.STRING)
    private EventStatus eventStatus;

    @OneToMany(mappedBy = "event", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Registration> participants = new ArrayList<>();

    // Helper methods for display of date
    public LocalDate getDate(LocalDateTime dateTime){
        return dateTime != null ? dateTime.toLocalDate() : null;
    }

    // Helper methods for display of time
    public LocalTime getTime(LocalDateTime dateTime){
        return dateTime != null ? dateTime.toLocalTime() : null;
    }


    @PrePersist
    private void prePersist() {
        this.isTicketed = false;
        this.isFeatured = false;

    }
}
