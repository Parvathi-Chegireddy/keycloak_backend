package com.spantag.oauth2_service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    // Auth service — saves OAuth2 user to the shared DB
    private final WebClient authClient = WebClient.builder()
            .baseUrl("http://localhost:9090")
            .build();

    // Profile service — issues JWT tokens
    private final WebClient profileClient = WebClient.builder()
            .baseUrl("http://localhost:9093")
            .build();

    private static final String FRONTEND_REDIRECT =
            "http://localhost:5173/oauth2/callback";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = oauthToken.getPrincipal();
        String provider      = oauthToken.getAuthorizedClientRegistrationId();

        // Extract user info from OAuth2 provider
        String name       = extractName(oauthUser, provider);
        String email      = extractEmail(oauthUser, provider);
        String avatarUrl  = extractAvatar(oauthUser, provider);
        String providerId = extractProviderId(oauthUser, provider);

        // ── Step 1: Save/update user in auth-service DB ──────────────
        Map<String, Object> savedUser = saveUserToDb(
                provider, providerId, name, email, avatarUrl);
        String resolvedUsername = savedUser != null ? str(savedUser.get("username")) : name;

        // ── Step 2: Issue JWT tokens via profile-service ──────────────
        Map<String, Object> profile = callProfileService(
                resolvedUsername, name, email, avatarUrl,
                "ROLE_USER", provider, "oauth2", response);

        // ── Step 3: Invalidate OAuth2 session ────────────────────────
        // The JWT is already in a HttpOnly cookie — no need to keep the session
        HttpSession session = request.getSession(false);
        if (session != null) session.invalidate();

        // ── Step 4: Redirect React with non-sensitive display data ────
        // The actual accessToken is NOT in the URL — it's in-memory on the frontend
        // The refreshToken is in the HttpOnly cookie forwarded by callProfileService
        String redirectUrl = FRONTEND_REDIRECT
                + "?username="    + encode(resolvedUsername)
                + "&displayName=" + encode(name)
                + "&email="       + encode(email)
                + "&avatar="      + encode(avatarUrl)
                + "&role="        + encode(str(profile.get("role")))
                + "&provider="    + encode(provider)
                + "&loginMethod=" + encode("oauth2")
                + "&roleLabel="   + encode(provider.toUpperCase() + " USER")
                + "&methodLabel=" + encode(cap(provider) + " OAuth2");

        System.out.printf("[OAUTH2] Login complete → username=%s provider=%s%n",
                resolvedUsername, provider);

        response.sendRedirect(redirectUrl);
    }

    /* ── Step 1: persist OAuth2 user via auth-service ─────────────── */

    @SuppressWarnings("unchecked")
    private Map<String, Object> saveUserToDb(String provider, String providerId,
                                              String name, String email, String avatarUrl) {
        try {
            Map<String, String> body = new HashMap<>();
            body.put("provider",   provider);
            body.put("providerId", providerId);
            body.put("username",   provider + "_" + sanitize(name));
            body.put("displayName", name);
            body.put("email",      email);
            body.put("avatar",     avatarUrl);

            Map<String, Object> result = authClient.post()
                    .uri("/api/auth/oauth2/save-user")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return result;
        } catch (Exception e) {
            System.err.println("[OAUTH2] Failed to save user to DB: " + e.getMessage());
            return null;
        }
    }

    /* ── Step 2: call profile service and forward Set-Cookie ─────── */

    @SuppressWarnings("unchecked")
    private Map<String, Object> callProfileService(
            String username, String displayName, String email, String avatar,
            String role, String provider, String loginMethod,
            HttpServletResponse httpResponse) {
        try {
            Map<String, String> body = new HashMap<>();
            body.put("username",    username);
            body.put("displayName", displayName);
            body.put("email",       email);
            body.put("avatar",      avatar);
            body.put("role",        role);
            body.put("provider",    provider);
            body.put("loginMethod", loginMethod);

            var result = profileClient.post()
                    .uri("/api/profile/token")
                    .bodyValue(body)
                    .exchangeToMono(clientResponse -> {
                        // Forward Set-Cookie (refreshToken) from profile service to browser
                        clientResponse.headers().asHttpHeaders()
                                .getValuesAsList("Set-Cookie")
                                .forEach(v -> httpResponse.addHeader("Set-Cookie", v));
                        return clientResponse.bodyToMono(Map.class);
                    })
                    .block();

            if (result != null) return new HashMap<>(result);

        } catch (Exception e) {
            System.err.println("[OAUTH2] Profile service error: " + e.getMessage());
        }

        // Fallback — return minimal profile data if service is down
        Map<String, Object> fb = new HashMap<>();
        fb.put("username",    username);
        fb.put("displayName", displayName);
        fb.put("role",        role);
        fb.put("provider",    provider);
        fb.put("loginMethod", loginMethod);
        return fb;
    }

    /* ── OAuth2 attribute extractors ────────────────────────────────── */

    private String extractName(OAuth2User user, String provider) {
        String name = user.getAttribute("name");
        if (name == null || name.isBlank()) name = user.getAttribute("login"); // GitHub
        return name != null ? name : "User";
    }

    private String extractEmail(OAuth2User user, String provider) {
        String email = user.getAttribute("email");
        return email != null ? email : provider + "@oauth2.user";
    }

    private String extractAvatar(OAuth2User user, String provider) {
        String pic = "google".equals(provider)
                ? user.getAttribute("picture")    // Google
                : user.getAttribute("avatar_url"); // GitHub
        return pic != null ? pic : "";
    }

    private String extractProviderId(OAuth2User user, String provider) {
        Object id = "google".equals(provider)
                ? user.getAttribute("sub")   // Google uses "sub"
                : user.getAttribute("id");   // GitHub uses "id" (Integer)
        return id != null ? id.toString() : user.getName();
    }

    /* ── Utilities ──────────────────────────────────────────────────── */

    private String sanitize(String name) {
        if (name == null) return "user";
        return name.toLowerCase()
                   .replaceAll("[^a-z0-9]", "_")
                   .replaceAll("_+", "_")
                   .replaceAll("^_|_$", "");
    }

    private String encode(String v) {
        return URLEncoder.encode(v != null ? v : "", StandardCharsets.UTF_8);
    }

    private String str(Object o) { return o != null ? o.toString() : ""; }

    private String cap(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
