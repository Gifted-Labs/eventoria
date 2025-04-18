package com.giftedlabs.eventoria.authentication.service.impl;

import com.giftedlabs.eventoria.authentication.dto.*;
import com.giftedlabs.eventoria.enums.UserRole;
import com.giftedlabs.eventoria.jwt.JwtService;
import com.giftedlabs.eventoria.users.User;
import com.giftedlabs.eventoria.users.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public MessageResponse registerUser(SignUpRequest signUpRequest) {
        // Check if username or email already exist;
        if (userRepository.existsByUsername(signUpRequest.username())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if(userRepository.existsByEmail(signUpRequest.email())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        if(userRepository.existsByPhoneNumber(signUpRequest.phoneNumber())) {
            return new MessageResponse("Error: Phone number is already in use!");
        }

        // Create new user
        User user = User.builder().
                firstName(signUpRequest.firstName()).
                lastName(signUpRequest.lastName()).
                username(signUpRequest.username()).
                email(signUpRequest.email()).
                password(passwordEncoder.encode(signUpRequest.password())).
                phoneNumber(signUpRequest.phoneNumber()).
                address(signUpRequest.address()).
                city(signUpRequest.city()).
                state(signUpRequest.state()).
                country(signUpRequest.country()).
                role(UserRole.ROLE_ATTENDEE).
                isEnabled(false).
                build();

        // Generate JWT token
        String token = jwtService.generateVerificationToken(user.getEmail());

        return new MessageResponse("User registered successfully! Verification token: " + token);
    }


    public JwtResponse authenticateUser(SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signInRequest.usernameOrEmail(), signInRequest.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtService.generateToke(authentication);
        String refreshToken = jwtService.generateVerificationToken(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        return new JwtResponse(
                jwt,
                refreshToken,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );
    }

    public MessageResponse verifyAccount(String token) {
        try {
            String email = jwtService.getEmailFromJwtToken(token);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Error: User is not found."));

            if(user.isEnabled()) {
                return new MessageResponse("Error: User is already verified.");
            }
                user.setEnabled(true);
                userRepository.save(user);
                return new MessageResponse("User verified successfully.");


            return new MessageResponse("Account verified successfully");
        }
        catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Verification token has expired");
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid verification token");
        }
    }


    public MessageResponse requestPasswordReset(PasswordResetRequest passwordResetRequest) {
        User user = userRepository.findByEmail()
                .orElseThrow(() -> new RuntimeException("Error: User is not found."));

        String token = jwtService.generateVerificationToken(user.getEmail());
        return new MessageResponse("Password reset token: " + token);
    }

    @Transactional
    public MessageResponse resetPassword(PasswordResetRequest passwordResetRequest) {

        // Check if password and confirm matches.
        if(!passwordResetRequest.newPassword().equals(passwordResetRequest.confirmPassword())  ) {
            return new MessageResponse("Error: Passwords do not match.");
        }

        try {
            String email = jwtService.getEmailFromJwtToken(passwordResetRequest.token());
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email/username: "+email));

            user.setPassword(passwordEncoder.encode(passwordResetRequest.newPassword()));
            userRepository.save(user);

            return new MessageResponse("Password reset successfully.");
        }
        catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Password reset token has expired");
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid password reset token");
        }
    }

    public JwtResponse refreshToken(String refreshToken) {
        try {
            if(!jwtService.validateJwtToken(refreshToken)) {
                throw new InvalidTokenException("Invalid refresh token");
            }

            String email = jwtService.getEmailFromJwtToken(refreshToken);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email/username: "+email));
            UserDetailsImpl userDetails = UserDetailsImpl.build(user);

            String newToken = jwtService.generateTokenFromEmail(email);
            String newRefreshToken = jwtService.generateRefreshToken(email);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).toList();

            return new JwtResponse(
                newToken,
                newRefreshToken,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles
            );
        }
        catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Refresh token has expired, please login again");
        }
    }
}
