package com.pragna.profile;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Profile Controller — Keycloak integrated
 *
 * POST /api/profile/token    → still called by auth/oauth2 services;
 *                               now proxies to Keycloak token endpoint
 * POST /api/profile/refresh  → proxies refresh to Keycloak
 * POST /api/profile/logout   → clears cookies
 * GET  /api/profile/validate → introspects token with Keycloak
 */
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final WebClient keycloakClient;
    private final String realm;
    private final String clientId;

    public ProfileController(
            @org.springframework.beans.factory.annotation.Value("${keycloak.auth-server-url}") String authServerUrl,
            @org.springframework.beans.factory.annotation.Value("${keycloak.realm}") String realm,
            @org.springframework.beans.factory.annotation.Value("${keycloak.client-id}") String clientId) {
        this.keycloakClient = WebClient.builder().baseUrl(authServerUrl).build();
        this.realm = realm;
        this.clientId = clientId;
    }

    // ── POST /api/profile/token ───────────────────────────────────────────
    // Called by auth-service and oauth2-service after login
    // Proxies direct grant to Keycloak
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestBody ProfileRequest req,
            HttpServletResponse response) {

        System.out.printf("[PROFILE] Token request for username=%s%n", req.getUsername());

        // If accessToken already present in request (forwarded by oauth2-service), return it
        if (req.getAccessToken() != null && !req.getAccessToken().isBlank()) {
            Map<String, Object> body = new HashMap<>();
            body.put("accessToken",  req.getAccessToken());
            body.put("username",     req.getUsername());
            body.put("displayName",  req.getDisplayName() != null ? req.getDisplayName() : req.getUsername());
            body.put("email",        nvl(req.getEmail()));
            body.put("role",         nvl(req.getRole(), "ROLE_USER"));
            body.put("provider",     nvl(req.getProvider(), "keycloak"));
            body.put("loginMethod",  nvl(req.getLoginMethod(), "keycloak"));
            body.put("expiresIn",    300);
            return ResponseEntity.ok(body);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("message", "Token issued via Keycloak — use /api/auth/login for direct token issuance");
        body.put("username", req.getUsername());
        return ResponseEntity.ok(body);
    }

    // ── POST /api/profile/refresh ─────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        String refreshToken = extractRefreshCookie(request);
        if (refreshToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token"));
        }

        try {
            String tokenUrl = "/realms/" + realm + "/protocol/openid-connect/token";

            @SuppressWarnings("unchecked")
            Map<String, Object> result = keycloakClient.post()
                    .uri(tokenUrl)
                    .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                    .bodyValue("grant_type=refresh_token"
                            + "&client_id=" + clientId
                            + "&refresh_token=" + refreshToken)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (result != null && result.containsKey("access_token")) {
                setRefreshTokenCookie(response, (String) result.get("refresh_token"));
                Map<String, Object> body = new HashMap<>();
                body.put("accessToken", result.get("access_token"));
                body.put("expiresIn",   result.get("expires_in"));
                return ResponseEntity.ok(body);
            }

            clearRefreshTokenCookie(response);
            return ResponseEntity.status(401).body(Map.of("error", "Refresh failed"));

        } catch (Exception e) {
            clearRefreshTokenCookie(response);
            return ResponseEntity.status(401).body(Map.of("error", "Refresh failed: " + e.getMessage()));
        }
    }

    // ── POST /api/profile/logout ──────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        clearRefreshTokenCookie(response);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ── GET /api/profile/validate ─────────────────────────────────────────
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "Missing Authorization header"));
        }

        // Introspect token with Keycloak
        try {
            String introUrl = "/realms/" + realm + "/protocol/openid-connect/userinfo";
            @SuppressWarnings("unchecked")
            Map<String, Object> userInfo = keycloakClient.get()
                    .uri(introUrl)
                    .header("Authorization", authHeader)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (userInfo != null) {
                Map<String, Object> body = new HashMap<>(userInfo);
                body.put("valid", true);
                return ResponseEntity.ok(body);
            }
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));

        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Token validation failed"));
        }
    }

    // ── Cookie helpers ────────────────────────────────────────────────────
    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        if (token == null) return;
        response.addHeader("Set-Cookie",
                "kc_refresh_token=" + token
                + "; Path=/api/profile/refresh"
                + "; HttpOnly; Max-Age=604800; SameSite=Strict");
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                "kc_refresh_token=; Path=/api/profile/refresh; HttpOnly; Max-Age=0; SameSite=Strict");
    }

    private String extractRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> "kc_refresh_token".equals(c.getName()))
                .map(jakarta.servlet.http.Cookie::getValue)
                .findFirst().orElse(null);
    }

    private String nvl(String v) { return v != null ? v : ""; }
    private String nvl(String v, String fallback) { return (v != null && !v.isBlank()) ? v : fallback; }
}
