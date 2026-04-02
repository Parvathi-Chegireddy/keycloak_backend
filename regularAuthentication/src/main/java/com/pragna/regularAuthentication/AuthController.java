package com.pragna.regularAuthentication;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final KeycloakAdminService keycloakAdminService;

    public AuthController(UserService userService,
                          AuthenticationManager authenticationManager,
                          KeycloakAdminService keycloakAdminService) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.keycloakAdminService = keycloakAdminService;
    }

    // ── POST /api/auth/register ───────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest req) {
        try {
            // 1. Save to local DB
            User user = new User();
            user.setUsername(req.getUsername());
            user.setPassword(req.getPassword());
            user.setEmail(req.getEmail());

            String role = (req.getRole() != null && !req.getRole().isBlank())
                    ? req.getRole() : "ROLE_USER";

            userService.registerUser(user, role);

            // 2. Create in Keycloak
            String keycloakId = keycloakAdminService.createKeycloakUser(
                    req.getUsername(), req.getPassword(), req.getEmail(), role);

            Map<String, String> res = new HashMap<>();
            res.put("message",    "User registered successfully");
            res.put("username",   req.getUsername());
            res.put("role",       role);
            res.put("keycloakId", keycloakId);
            return ResponseEntity.status(HttpStatus.CREATED).body(res);

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    // ── POST /api/auth/login ──────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest req,
            HttpServletResponse httpResponse) {
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
            );

            Map<String, Object> keycloakTokens = keycloakAdminService
                    .obtainToken(req.getUsername(), req.getPassword());

            if (keycloakTokens.containsKey("error")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Keycloak authentication failed"));
            }

            String accessToken  = (String) keycloakTokens.get("access_token");
            String refreshToken = (String) keycloakTokens.get("refresh_token");
            Object expiresIn    = keycloakTokens.get("expires_in");


            setRefreshTokenCookie(httpResponse, refreshToken);

            boolean isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            Map<String, Object> response = new HashMap<>();
            response.put("message",      "Login successful");
            response.put("accessToken",  accessToken);
            response.put("username",     req.getUsername());
            response.put("role",         isAdmin ? "ROLE_ADMIN" : "ROLE_USER");
            response.put("expiresIn",    expiresIn);
            response.put("loginMethod",  "keycloak");
            response.put("provider",     "keycloak");
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid username or password"));
        } catch (Exception ex) {
            System.err.println("[AUTH] Login error: " + ex.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Login failed: " + ex.getMessage()));
        }
    }

    // ── POST /api/auth/logout ─────────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse httpResponse) {
        clearRefreshTokenCookie(httpResponse);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ── POST /api/auth/refresh ────────────────────────────────────────────
    // Refresh Keycloak access token using the refresh_token cookie
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            jakarta.servlet.http.HttpServletRequest request,
            HttpServletResponse httpResponse) {
        String refreshToken = extractRefreshCookie(request);
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "No refresh token"));
        }
        try {
            Map<String, Object> tokens = keycloakAdminService.refreshToken(refreshToken);
            String newAccessToken  = (String) tokens.get("access_token");
            String newRefreshToken = (String) tokens.get("refresh_token");
            setRefreshTokenCookie(httpResponse, newRefreshToken);

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            response.put("expiresIn",   tokens.get("expires_in"));
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            clearRefreshTokenCookie(httpResponse);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Refresh failed: " + e.getMessage()));
        }
    }

    // Called by oauth2-service after provider login
    @PostMapping("/oauth2/save-user")
    public ResponseEntity<Map<String, Object>> saveOAuth2User(
            @RequestBody Map<String, String> req) {
        try {
            String username    = req.getOrDefault("username",    "");
            String email       = req.getOrDefault("email",       "");
            String displayName = req.getOrDefault("displayName", username);
            String avatar      = req.getOrDefault("avatar",      "");
            String provider    = req.getOrDefault("provider",    "oauth2");

            if (userService.findByUsername(username) == null) {
                User oauthUser = new User();
                oauthUser.setUsername(username);
                oauthUser.setPassword(java.util.UUID.randomUUID().toString());
                oauthUser.setEmail(email);
                oauthUser.setDisplayName(displayName);
                oauthUser.setAvatarUrl(avatar);
                oauthUser.setProvider(provider);
                userService.registerUser(oauthUser, "ROLE_USER");

                if (!keycloakAdminService.userExistsInKeycloak(username)) {
                    String randomPass = java.util.UUID.randomUUID().toString();
                    keycloakAdminService.createKeycloakUser(username, randomPass, email, "ROLE_USER");
                }
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("message",     "OAuth2 user saved");
            resp.put("username",    username);
            resp.put("displayName", displayName);
            resp.put("provider",    provider);
            return ResponseEntity.ok(resp);

        } catch (Exception e) {
            System.err.println("[AUTH] OAuth2 save-user failed: " + e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("message", "OAuth2 registration failed"));
        }
    }


    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        if (token == null) return;
        response.addHeader("Set-Cookie",
                "kc_refresh_token=" + token
                + "; Path=/api/auth/refresh"
                + "; HttpOnly"
                + "; Max-Age=604800"
                + "; SameSite=Strict");
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                "kc_refresh_token=; Path=/api/auth/refresh; HttpOnly; Max-Age=0; SameSite=Strict");
    }

    private String extractRefreshCookie(jakarta.servlet.http.HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (var cookie : request.getCookies()) {
            if ("kc_refresh_token".equals(cookie.getName())) return cookie.getValue();
        }
        return null;
    }
}
