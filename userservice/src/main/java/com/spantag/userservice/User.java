package com.spantag.userservice;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true)
    private String email;

    private boolean enabled = true;

    // OAuth2 fields — null for regular users
    @Column(name = "provider")
    private String provider;        // "google", "github", null for local

    @Column(name = "provider_id")
    private String providerId;      // OAuth2 subject ID

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "avatar_url")
    private String avatarUrl;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.MERGE)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    // Getters & Setters
    public Long getId()               { return id; }
    public void setId(Long id)        { this.id = id; }

    public String getUsername()               { return username; }
    public void setUsername(String username)  { this.username = username; }

    public String getPassword()               { return password; }
    public void setPassword(String password)  { this.password = password; }

    public String getEmail()                  { return email; }
    public void setEmail(String email)        { this.email = email; }

    public boolean isEnabled()                { return enabled; }
    public void setEnabled(boolean enabled)   { this.enabled = enabled; }

    public String getProvider()               { return provider; }
    public void setProvider(String provider)  { this.provider = provider; }

    public String getProviderId()                 { return providerId; }
    public void setProviderId(String providerId)  { this.providerId = providerId; }

    public String getDisplayName()                    { return displayName; }
    public void setDisplayName(String displayName)    { this.displayName = displayName; }

    public String getAvatarUrl()                  { return avatarUrl; }
    public void setAvatarUrl(String avatarUrl)    { this.avatarUrl = avatarUrl; }

    public Set<Role> getRoles()               { return roles; }
    public void setRoles(Set<Role> roles)     { this.roles = roles; }
}