package com.harumnusantara.user.controller;

import com.harumnusantara.user.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
@Slf4j
@CrossOrigin(origins = "*", maxAge = 3600)
public class PublicController {

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> info() {
        log.debug("Accessing public info");

        Map<String, Object> info = new HashMap<>();
        info.put("message", "Welcome to User Service");
        info.put("version", "1.0.0");
        info.put("description", "Spring Boot Authentication and Authorization Service");
        info.put("author", "aziz");
        info.put("timestamp", java.time.Instant.now().toString());

        ApiResponse<Map<String, Object>> response = ApiResponse.success(
                "public information retrieved successfully", info);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> healthCheck() {
        log.debug("Public health check request");

        ApiResponse<String> response = ApiResponse.success(
                "Service is running", "OK"
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/time")
    public ResponseEntity<ApiResponse<Map<String, String>>> getCurrentTime() {
        log.debug("Public time request");

        Map<String, String> time = new HashMap<>();
        time.put("serverTime", java.time.Instant.now().toString());
        time.put("timezone", java.time.ZoneId.systemDefault().toString());

        ApiResponse<Map<String, String>> timeInfo = ApiResponse.success(
                "Current time retrieved successfully", time
        );

        return new ResponseEntity<>(timeInfo, HttpStatus.OK);
    }

}
