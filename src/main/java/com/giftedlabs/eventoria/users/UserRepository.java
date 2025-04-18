package com.giftedlabs.eventoria.users;

import com.giftedlabs.eventoria.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByPhoneNumber(String phoneNumber);

    Optional<User> findByUsername(String username);

    List<User> findUserByFirstName(String firstName);

    List<User> findUserByLastName(String lastName);

    List<User> findByRole(UserRole role);

    List<User> findByFirstNameOrLastNameContainingIgnoreCase(String name);

    boolean existsByEmail(String email);

    boolean existsByPhoneNumber(String phoneNumber);

    boolean existsByUsername(String username);
}
