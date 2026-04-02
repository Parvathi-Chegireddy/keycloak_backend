package com.spantag.userservice;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /* ═══════════════════════════════════════════════════════
       USER ENDPOINTS
       @PreAuthorize enforces role — Spring Security throws 403
       automatically if the condition fails.
       ═══════════════════════════════════════════════════════ */

    /**
     * GET /api/user/me
     * Any authenticated user can fetch their own profile.
     * Principal.getName() returns the username from GatewayAuthFilter.
     */
    @GetMapping("/api/user/me")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getMyProfile(Principal principal) {

        return userRepository.findByUsername(principal.getName())
                .map(user -> ResponseEntity.ok(toProfileMap(user)))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found")));
    }

    /**
     * PUT /api/user/me
     * Any authenticated user can update their own profile.
     */
    @PutMapping("/api/user/me")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> updateMyProfile(
            Principal principal,
            @RequestBody UpdateProfileRequest req) {

        return userRepository.findByUsername(principal.getName())
                .map(user -> {
                    if (req.getEmail() != null && !req.getEmail().isBlank()) {
                        // Check email not already taken by another user
                        boolean emailTaken = userRepository.existsByEmail(req.getEmail())
                                && !req.getEmail().equalsIgnoreCase(user.getEmail());
                        if (emailTaken) {
                            return ResponseEntity.status(HttpStatus.CONFLICT)
                                    .<Map<String, Object>>body(
                                            Map.of("message", "Email already in use"));
                        }
                        user.setEmail(req.getEmail().trim().toLowerCase());
                    }
                    if (req.getDisplayName() != null && !req.getDisplayName().isBlank())
                        user.setDisplayName(req.getDisplayName().trim());
                    if (req.getAvatarUrl() != null && !req.getAvatarUrl().isBlank())
                        user.setAvatarUrl(req.getAvatarUrl().trim());

                    userRepository.save(user);
                    return ResponseEntity.ok(toProfileMap(user));
                })
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found")));
    }

    /* ═══════════════════════════════════════════════════════
       ADMIN ENDPOINTS
       @PreAuthorize("hasRole('ADMIN')") — Spring Security
       automatically returns 403 for non-admins.
       ═══════════════════════════════════════════════════════ */

    /**
     * GET /api/admin/users
     * Lists all users. ADMIN only.
     */
    @GetMapping("/api/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {
        List<Map<String, Object>> users = userRepository.findAll()
                .stream()
                .map(this::toProfileMap)
                .toList();
        return ResponseEntity.ok(users);
    }

    /**
     * GET /api/admin/users/{id}
     * Get a specific user by ID. ADMIN only.
     */
    @GetMapping("/api/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(user -> ResponseEntity.ok(toProfileMap(user)))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found")));
    }

    /**
     * PUT /api/admin/users/{id}/enable
     * Enable or disable a user. ADMIN only.
     */
    @PutMapping("/api/admin/users/{id}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> setUserEnabled(
            @PathVariable Long id,
            @RequestParam boolean enabled) {

        return userRepository.findById(id)
                .map(user -> {
                    user.setEnabled(enabled);
                    userRepository.save(user);
                    return ResponseEntity.ok(toProfileMap(user));
                })
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found")));
    }

    /**
     * PUT /api/admin/users/{id}
     * Admin updates any user's profile. ADMIN only.
     */
    @PutMapping("/api/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> updateUser(
            @PathVariable Long id,
            @RequestBody UpdateProfileRequest req) {

        return userRepository.findById(id)
                .map(user -> {
                    if (req.getDisplayName() != null && !req.getDisplayName().isBlank())
                        user.setDisplayName(req.getDisplayName().trim());
                    if (req.getEmail() != null && !req.getEmail().isBlank())
                        user.setEmail(req.getEmail().trim().toLowerCase());
                    userRepository.save(user);
                    return ResponseEntity.ok(toProfileMap(user));
                })
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found")));
    }

    /**
     * DELETE /api/admin/users/{id}
     * Delete a user. ADMIN only.
     */
    @DeleteMapping("/api/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User not found"));
        }
        userRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    /* ── helper ──────────────────────────────────────────── */

    private Map<String, Object> toProfileMap(User user) {
        Map<String, Object> map = new HashMap<>();
        map.put("id",          user.getId());
        map.put("username",    user.getUsername());
        map.put("email",       user.getEmail() != null ? user.getEmail() : "");
        map.put("displayName", user.getDisplayName() != null
                               ? user.getDisplayName() : user.getUsername());
        map.put("avatarUrl",   user.getAvatarUrl() != null ? user.getAvatarUrl() : "");
        map.put("enabled",     user.isEnabled());
        map.put("provider",    user.getProvider() != null ? user.getProvider() : "local");
        map.put("roles",       user.getRoles().stream()
                                   .map(Role::getName).toList());
        return map;
    }
}