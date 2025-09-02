package com.harumnusantara.user.service;

import com.harumnusantara.user.dto.JwtAuthenticationResponse;
import com.harumnusantara.user.dto.LoginRequest;
import com.harumnusantara.user.dto.SignUpRequest;
import com.harumnusantara.user.dto.UserInfo;
import com.harumnusantara.user.exception.BadRequestException;
import com.harumnusantara.user.exception.ResourceNotFoundException;
import com.harumnusantara.user.model.Role;
import com.harumnusantara.user.model.User;
import com.harumnusantara.user.repository.UserRepository;
import com.harumnusantara.user.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest) {
        log.info("Attempting authentication for user: {}", loginRequest.getUsernameOrEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtTokenProvider.generateToken(authentication);

            User user = (User) authentication.getPrincipal();

            UserInfo userInfo = createUserInfo(user);

            Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(jwt) / 1000;

            log.info("Authentication successful for user: {}", user.getUsername());

            return new JwtAuthenticationResponse(jwt, expiresIn, userInfo);

        } catch (AuthenticationException ex) {
            log.error("Authentication failed for user: {} - {}",
                    loginRequest.getUsernameOrEmail(), ex.getMessage());
            throw new BadCredentialsException("Invalid username or password", ex);
        }
    }

    public JwtAuthenticationResponse registerUser(SignUpRequest signUpRequest) {
        log.info("Attempting registration for user: {} with email: {}",
                signUpRequest.getUsername(), signUpRequest.getEmail());

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            log.warn("Registration failed - Username already taken: {}", signUpRequest.getUsername());
            throw new BadRequestException("Username already taken");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.warn("Registration failed - Email already taken: {}", signUpRequest.getEmail());
            throw new BadRequestException("Email already taken");
        }

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .fullName(signUpRequest.getFullName())
                .build();

        user.setRole(Role.USER);

        User savedUser = userRepository.save(user);
        log.info("Registration successful for user: {}", savedUser.getUsername());

        String jwt = jwtTokenProvider.generateTokenFromUsername(savedUser.getUsername());

        UserInfo userInfo = createUserInfo(savedUser);

        Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(jwt) / 1000;

        return new JwtAuthenticationResponse(jwt, expiresIn, userInfo);
    }

    private UserInfo createUserInfo(User user) {
        return new UserInfo(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getRole().name()
        );
    }

    @Transactional(readOnly = true)
    public UserInfo getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadRequestException("User is not authenticated");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        User currentUser = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        log.debug("Retrieved current user: {}", currentUser.getUsername());
        return createUserInfo(currentUser);
    }

    @Transactional(readOnly = true)
    public boolean validateToken(String token) {
        try {
            if (jwtTokenProvider.validateToken(token)) {
                String username = jwtTokenProvider.getUsernameFromToken(token);
                return userRepository.findByUsername(username).isPresent();
            }
            return false;
        } catch (Exception ex) {
            log.error("Token validation error: {}", ex.getMessage());
            return false;
        }
    }

    public JwtAuthenticationResponse refreshToken(String token) {
        if (!jwtTokenProvider.validateToken(token)) {
            throw new BadRequestException("Token is invalid or expired");
        }

        String username = jwtTokenProvider.getUsernameFromToken(token);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String newToken = jwtTokenProvider.generateTokenFromUsername(username);
        Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(newToken) / 1000;
        UserInfo userInfo = createUserInfo(user);

        log.info("Token refreshed for user: {}", username);

        return new JwtAuthenticationResponse(newToken, expiresIn, userInfo);
    }

    public String logoutUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            User user = (User) authentication.getPrincipal();
            log.info("User logged out: {}", user.getUsername());

            SecurityContextHolder.clearContext();

            return "Logout successful";
        }
        return "User is not in session";
    }

    public String changePassword(String oldPassword, String newPassword) {
        User currentUser = getCurrentUserEntity();

        if (!passwordEncoder.matches(oldPassword, currentUser.getPassword())) {
            throw new BadRequestException("Old password is incorrect");
        }

        if (passwordEncoder.matches(newPassword, currentUser.getPassword())) {
            throw new BadRequestException("New password cannot be the same as the old password");
        }

        currentUser.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(currentUser);

        log.info("Password changed for user: {}", currentUser.getUsername());

        return "Password changed successfully";

    }

    private User getCurrentUserEntity() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadRequestException("User is not authenticated");
        }

        User user = (User) authentication.getPrincipal();

        return userRepository.findById(user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }


}
