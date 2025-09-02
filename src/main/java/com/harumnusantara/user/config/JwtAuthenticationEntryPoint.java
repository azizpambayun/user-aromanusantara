package com.harumnusantara.user.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {


    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        log.error("Unauthorized Error: {} - Attempting to access {} {}",
                authException.getMessage(),
                request.getMethod(),
                request.getRequestURI());

        String userAgent = request.getHeader("User-Agent");
        String remoteAddr = getClientIPAddress(request);
        log.debug("Unauthorized Access from IP: {}, User Agent: {}", remoteAddr, userAgent);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);


        Map<String, Object> responseBody = createErrorResponseBody(request, authException);

        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), responseBody);
    }

    private Map<String, Object> createErrorResponseBody(HttpServletRequest request,
                                                        AuthenticationException authException) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", false);
        responseBody.put("timestamp", java.time.Instant.now().toString());
        responseBody.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        responseBody.put("error", "Unauthorized");
        responseBody.put("message", getErrorMessage(authException));
        responseBody.put("path", request.getRequestURI());

        if (isDevelopmentEnvironment()) {
            responseBody.put("method", request.getMethod());
            responseBody.put("exception", authException.getClass().getSimpleName());
        }

        return responseBody;
    }

    private String getErrorMessage(AuthenticationException authException) {
        String errorMessage = authException.getMessage();

        if (errorMessage == null || errorMessage.isEmpty()) {
            return "Access Denied, please login first";
        }

        if (errorMessage.toLowerCase().contains("token") ||
                errorMessage.toLowerCase().contains("jwt")) {
            return "Token is invalid or expired, please login again";
        }

        if (errorMessage.toLowerCase().contains("credentials")) {
            return "Credentials are invalid, please check your username and password";
        }

        return "Access Denied, You don't have permission to access this resource";
    }

    private String getClientIPAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_CLIENT_IP",
                "HTTP_X_FORWARDED_FOR",
                "X-Real-IP",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }
        return request.getRemoteAddr();
    }

    private boolean isDevelopmentEnvironment() {
        String activeProfiles = System.getProperty("spring.profiles.active");
        return activeProfiles != null && (activeProfiles.contains("dev")
                || activeProfiles.contains("development")
                || activeProfiles.contains("local")
        );
    }


}
