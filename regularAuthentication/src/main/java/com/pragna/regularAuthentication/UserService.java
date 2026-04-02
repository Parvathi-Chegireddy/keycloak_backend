package com.pragna.regularAuthentication;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository  = userRepository;
        this.roleRepository  = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Register a new user.
     * Throws RuntimeException if username or email is already taken.
     */
    public User registerUser(User user, String roleName) {
        // Guard against duplicate username
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username '" + user.getUsername() + "' is already taken");
        }
        // Guard against duplicate email (only if email was provided)
        if (user.getEmail() != null && !user.getEmail().isBlank()
                && userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email '" + user.getEmail() + "' is already in use");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getProvider() == null) {
            user.setProvider("local");
        }

        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            throw new RuntimeException("Role not found: " + roleName);
        }

        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);

        return userRepository.save(user);
    }

    /**
     * Save or update an OAuth2 user.
     * If user with same provider+providerId exists, updates their info.
     * Otherwise creates a new account.
     */
    public User saveOAuthUser(String provider, String providerId,
                              String name, String email, String avatarUrl) {

        var existing = userRepository.findByProviderAndProviderId(provider, providerId);

        if (existing.isPresent()) {
            User user = existing.get();
            user.setDisplayName(name);
            user.setEmail(email);
            user.setAvatarUrl(avatarUrl);
            return userRepository.save(user);
        }

        User user = new User();

        // Generate unique username: "google_raju", "github_user_2", etc.
        String baseUsername = provider + "_" + sanitize(name);
        user.setUsername(uniqueUsername(baseUsername));

        // Random unusable password — OAuth2 users never use password login
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));

        user.setEmail(email);
        user.setDisplayName(name);
        user.setAvatarUrl(avatarUrl);
        user.setProvider(provider);
        user.setProviderId(providerId);
        user.setEnabled(true);

        Role role = roleRepository.findByName("ROLE_USER");
        if (role == null) {
            throw new RuntimeException("ROLE_USER not found — run DataInitializer first");
        }
        user.setRoles(Set.of(role));

        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    /* ── helpers ─────────────────────────────────────────── */

    private String sanitize(String name) {
        if (name == null) return "user";
        return name.toLowerCase()
                   .replaceAll("[^a-z0-9]", "_")
                   .replaceAll("_+", "_")
                   .replaceAll("^_|_$", "");
    }

    private String uniqueUsername(String base) {
        if (!userRepository.existsByUsername(base)) return base;
        int suffix = 2;
        while (userRepository.existsByUsername(base + "_" + suffix)) suffix++;
        return base + "_" + suffix;
    }
}
