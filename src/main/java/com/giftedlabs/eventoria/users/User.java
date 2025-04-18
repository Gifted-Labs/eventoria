package com.giftedlabs.eventoria.users;

import com.giftedlabs.eventoria.enums.UserRole;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.NaturalId;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
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
    private String email;
    private String password;
    @NaturalId(mutable = false)
    private String phoneNumber;
    private UserRole role;
    private String address;
    private String city;
    private String state;
    private String country;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean isEnabled = false;




    // Add any other fields or methods as needed
}
