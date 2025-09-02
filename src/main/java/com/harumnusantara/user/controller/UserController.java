package com.harumnusantara.user.controller;

import com.harumnusantara.user.dto.ApiResponse;
import com.harumnusantara.user.dto.UpdateProfileRequest;
import com.harumnusantara.user.exception.ResourceNotFoundException;
import com.harumnusantara.user.model.User;
import com.harumnusantara.user.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(value = "*", maxAge = 3600)
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserProfile() {
        log.debug("User profile request");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("fullName", user.getFullName());
        profile.put("role", user.getRole().name());
        profile.put("authorities", user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        profile.put("accountNonExpired", user.isAccountNonExpired());
        profile.put("accountNonLocked", user.isAccountNonLocked());
        profile.put("credentialsNonExpired", user.isCredentialsNonExpired());
        profile.put("enabled", user.isEnabled());

        ApiResponse<Map<String, Object>> response = ApiResponse.success(
                "user profile retrieved successfully", profile
        );

        log.debug("User profile retrieved for: {}", user.getUsername());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserDashboard() {
        log.debug("User dashboard request");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        Map<String, Object> dashboardData = new HashMap<>();
        dashboardData.put("welcomeMessage", "Welcome, " + user.getFullName() + "!");
        dashboardData.put("lastLogin", java.time.Instant.now().toString());

        ApiResponse<Map<String, Object>> response = ApiResponse.success(
                "Dashboard data retrieved successfully", dashboardData
        );

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<ApiResponse<String>> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request) {

        log.debug("Profile update request");

        // Get current user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUserPrincipal = (User) authentication.getPrincipal();
        Long currentUserId = currentUserPrincipal.getId();

        User userToUpdate = userRepository.findById(currentUserId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: {}" + currentUserId));

        // Updating data
        userToUpdate.setFullName(request.getFullName());

        // save to the database
        userRepository.save(userToUpdate);

        // Create a success response
        ApiResponse<String> response = ApiResponse.success(
                "Profile updated successfully"
        );

        log.debug("Profile updated for user: {}", userToUpdate.getUsername());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
