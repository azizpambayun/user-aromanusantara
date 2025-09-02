package com.harumnusantara.user.controller;

import com.harumnusantara.user.dto.ApiResponse;
import com.harumnusantara.user.dto.UserInfo;
import com.harumnusantara.user.model.User;
import com.harumnusantara.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@Slf4j
@CrossOrigin(origins = "*", maxAge = 3600)
@RequiredArgsConstructor
public class AdminController {

    private final UserRepository userRepository;


    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<UserInfo>>> getAllUsers() {
        log.debug("Request for getting all users");

        List<User> users = userRepository.findAll();
        List<UserInfo> userInfoList = users.stream()
                .map(user -> new UserInfo(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getFullName(),
                        user.getRole().name()
                ))
                .toList();

        ApiResponse<List<UserInfo>> response = ApiResponse.success(
                "User list retrieved successfully", userInfoList
        );

        log.debug("Retrieved {} users for admin", userInfoList.size());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSystemStats() {
        log.debug("System stats request (admin only)");

        long totalUsers = userRepository.count();
        long adminCount = userRepository.findAll().stream()
                .filter(user -> user.getRole().name().equals("ADMIN"))
                .count();
        long userCount = totalUsers - adminCount;

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalUsers", totalUsers);
        stats.put("adminUsers", adminCount);
        stats.put("regularUsers", userCount);
        stats.put("lastUpdated", java.time.Instant.now().toString());

        ApiResponse<Map<String, Object>> response = ApiResponse.success(
                "System statistics retrieved successfully", stats
        );

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAdminDashboard() {
        log.debug("Admin dashboard request");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User admin = (User) authentication.getPrincipal();

        Map<String, Object> dashboardData = new HashMap<>();
        dashboardData.put("adminName", admin.getFullName());
        dashboardData.put("totalUsers", userRepository.count());
        dashboardData.put("systemStatus", "Running");
        dashboardData.put("lastActivity", java.time.Instant.now().toString());

        ApiResponse<Map<String, Object>> response = ApiResponse.success(
                "Admin dashboard data retrieved successfully", dashboardData
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

}
