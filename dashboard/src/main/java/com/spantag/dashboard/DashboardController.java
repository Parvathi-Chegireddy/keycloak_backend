package com.spantag.dashboard;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DashboardController {

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminDashboard(Principal principal) {
        return Map.of(
                "message",   "Welcome to Admin Dashboard",
                "username",  principal.getName(),
                "role",      "ADMIN",
                "service",   "dashboard-service:9094",
                "timestamp", LocalDateTime.now()
                        .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        );
    }

    
    @GetMapping("/user/dashboard")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Map<String, Object> userDashboard(Principal principal) {
        return Map.of(
                "message",   "Welcome to User Dashboard",
                "username",  principal.getName(),
                "service",   "dashboard-service:9094",
                "timestamp", LocalDateTime.now()
                        .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        );
    }
}
