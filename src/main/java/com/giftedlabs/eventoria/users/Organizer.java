package com.giftedlabs.eventoria.users;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.giftedlabs.eventoria.enums.VerificationStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.List;



@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@SuperBuilder
@DiscriminatorValue("ORGANIZER")
public class Organizer extends User{

    private String organizationName;
    private String logoUrl;
    private VerificationStatus verificationStatus;

    @OneToMany(mappedBy = "organizer", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private List<Event> events;
}
