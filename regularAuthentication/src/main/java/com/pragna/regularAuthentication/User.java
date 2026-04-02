package com.pragna.regularAuthentication;

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

    // OAuth2 fields — null for regular username/password users
    @Column(name = "provider")
    private String provider;          // "google", "github", null = local

    @Column(name = "provider_id")
    private String providerId;        // OAuth2 sub/id from provider

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
    public Long getId()              { return id; }
    public void setId(Long id)       { this.id = id; }

    public String getUsername()              { return username; }
    public void setUsername(String v)        { this.username = v; }

    public String getPassword()              { return password; }
    public void setPassword(String v)        { this.password = v; }

    public String getEmail()                 { return email; }
    public void setEmail(String v)           { this.email = v; }

    public boolean isEnabled()               { return enabled; }
    public void setEnabled(boolean v)        { this.enabled = v; }

    public String getProvider()              { return provider; }
    public void setProvider(String v)        { this.provider = v; }

    public String getProviderId()            { return providerId; }
    public void setProviderId(String v)      { this.providerId = v; }

    public String getDisplayName()           { return displayName; }
    public void setDisplayName(String v)     { this.displayName = v; }

    public String getAvatarUrl()             { return avatarUrl; }
    public void setAvatarUrl(String v)       { this.avatarUrl = v; }

    public Set<Role> getRoles()              { return roles; }
    public void setRoles(Set<Role> roles)    { this.roles = roles; }
}