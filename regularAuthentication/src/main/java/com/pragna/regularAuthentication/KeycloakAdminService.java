package com.pragna.regularAuthentication;

import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakAdminService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin.client-id}")
    private String adminClientId;

    @Value("${keycloak.admin.client-secret}")
    private String adminClientSecret;

    @Value("${keycloak.client-id}")
    private String clientId;

    // ── Admin Keycloak instance ───────────────────────────────────────────
    private Keycloak getAdminKeycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm("spantag")
                .clientId(adminClientId)
                .clientSecret(adminClientSecret)
                .grantType("client_credentials")
                .build();
    }

    // ── Create user in Keycloak ───────────────────────────────────────────
    public String createKeycloakUser(String username, String password,
                                     String email, String roleName) {
        try (Keycloak kc = getAdminKeycloak()) {
            RealmResource realmResource = kc.realm(realm);
            UsersResource usersResource = realmResource.users();

            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            user.setEmail((email != null && !email.isBlank()) ? email : null);
            user.setEmailVerified(true);
            user.setEnabled(true);
            user.setRequiredActions(Collections.emptyList()); // no required actions

            try (Response response = usersResource.create(user)) {
                int status = response.getStatus();

                if (status == 201) {
                    String location = response.getHeaderString("Location");
                    String userId = location.substring(location.lastIndexOf("/") + 1);

                    // Set password — temporary MUST be false
                    setPassword(usersResource, userId, password);

                    // Assign realm role
                    assignRealmRole(realmResource, userId, roleName);

                    System.out.printf("[KEYCLOAK] Created user: %s (id=%s)%n", username, userId);
                    return userId;

                } else if (status == 409) {
                    System.out.printf("[KEYCLOAK] User already exists: %s%n", username);
                    // Find and return existing user ID
                    List<UserRepresentation> existing = usersResource.search(username, true);
                    if (!existing.isEmpty()) {
                        String existingId = existing.get(0).getId();
                        // Reset password for existing user too
                        setPassword(usersResource, existingId, password);
                        return existingId;
                    }
                    return "existing-user";

                } else {
                    throw new RuntimeException(
                            "Failed to create Keycloak user, HTTP status: " + status);
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Keycloak user creation error: " + e.getMessage(), e);
        }
    }

    // ── Set password — temporary=false is critical ────────────────────────
    private void setPassword(UsersResource usersResource, String userId, String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false); // MUST be false — prevents "Account not fully set up"
        usersResource.get(userId).resetPassword(credential);
        System.out.printf("[KEYCLOAK] Password set for userId=%s%n", userId);
    }

    // ── Assign realm role ─────────────────────────────────────────────────
    private void assignRealmRole(RealmResource realmResource,
                                 String userId, String roleName) {
        try {
            String kcRoleName = (roleName != null && roleName.contains("ADMIN"))
                    ? "admin" : "user";
            RoleRepresentation role = realmResource.roles()
                    .get(kcRoleName).toRepresentation();
            realmResource.users().get(userId).roles()
                    .realmLevel().add(List.of(role));
            System.out.printf("[KEYCLOAK] Assigned role '%s' to userId=%s%n",
                    kcRoleName, userId);
        } catch (Exception e) {
            System.err.println("[KEYCLOAK] Role assignment error: " + e.getMessage());
        }
    }

    // ── Obtain token via direct password grant ────────────────────────────
    public Map<String, Object> obtainToken(String username, String password) {
        String tokenUrl = authServerUrl + "/realms/" + realm
                + "/protocol/openid-connect/token";

        String body = "grant_type=password"
                + "&client_id=" + encode(clientId)
                + "&username=" + encode(username)
                + "&password=" + encode(password);

        System.out.printf("[KEYCLOAK] Requesting token for user=%s at %s%n",
                username, tokenUrl);

        try {
            WebClient webClient = WebClient.create();

            @SuppressWarnings("unchecked")
            Map<String, Object> result = webClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .bodyValue(body)
                    .retrieve()
                    .onStatus(
                        status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> clientResponse.bodyToMono(String.class)
                            .map(errorBody -> {
                                System.err.println("[KEYCLOAK] Token error response: " + errorBody);
                                return new RuntimeException("Keycloak token error: " + errorBody);
                            })
                    )
                    .bodyToMono(Map.class)
                    .block();

            if (result != null && result.containsKey("access_token")) {
                System.out.println("[KEYCLOAK] Token obtained successfully");
                return result;
            }

            return Map.of("error", "No access_token in response");

        } catch (WebClientResponseException e) {
            String errorBody = e.getResponseBodyAsString();
            System.err.println("[KEYCLOAK] Token 4xx/5xx: " + e.getStatusCode()
                    + " body=" + errorBody);
            throw new RuntimeException("Authentication failed: " + errorBody);

        } catch (Exception e) {
            System.err.println("[KEYCLOAK] Token error: " + e.getMessage());
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }

    // ── Refresh token ─────────────────────────────────────────────────────
    public Map<String, Object> refreshToken(String refreshToken) {
        String tokenUrl = authServerUrl + "/realms/" + realm
                + "/protocol/openid-connect/token";

        String body = "grant_type=refresh_token"
                + "&client_id=" + encode(clientId)
                + "&refresh_token=" + encode(refreshToken);

        try {
            WebClient webClient = WebClient.create();

            @SuppressWarnings("unchecked")
            Map<String, Object> result = webClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return result != null ? result : Map.of("error", "No response");

        } catch (Exception e) {
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        }
    }

    // ── Logout user ───────────────────────────────────────────────────────
    public void logoutUser(String keycloakUserId) {
        try (Keycloak kc = getAdminKeycloak()) {
            kc.realm(realm).users().get(keycloakUserId).logout();
        } catch (Exception e) {
            System.err.println("[KEYCLOAK] Logout error: " + e.getMessage());
        }
    }

    // ── Check if user exists ──────────────────────────────────────────────
    public boolean userExistsInKeycloak(String username) {
        try (Keycloak kc = getAdminKeycloak()) {
            List<UserRepresentation> users = kc.realm(realm).users()
                    .search(username, true);
            return !users.isEmpty();
        } catch (Exception e) {
            System.err.println("[KEYCLOAK] userExists error: " + e.getMessage());
            return false;
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value != null ? value : "", StandardCharsets.UTF_8);
    }
}