package com.giftedlabs.eventoria.users;

import com.giftedlabs.eventoria.enums.UserRole;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.NaturalId;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Entity
@Inheritance(strategy = InheritanceType.JOINED)
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    private String username;

    @Valid
    @NaturalId(mutable = false)
    @Column(unique = true, nullable = false)
    private String email;
    private String password;

    @Column(unique = true, nullable = false)
    @NaturalId(mutable = false)
    private String phoneNumber;
    @Enumerated(EnumType.ORDINAL)
    private UserRole role;
    private String address;
    private String city;
    private String state;
    private String country;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean isEnabled = false;


    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // Add any other fields or methods as needed
}
