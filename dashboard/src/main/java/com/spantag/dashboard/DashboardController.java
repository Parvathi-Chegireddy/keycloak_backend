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

    /**
     * GET /api/admin/dashboard
     * ADMIN only — returns admin stats/welcome.
     * Spring Security automatically returns 403 for ROLE_USER.
     */
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

    /**
     * GET /api/user/dashboard
     * Both ROLE_USER and ROLE_ADMIN can access.
     */
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