package com.pragna.profile;

public class ProfileRequest {
    private String username;
    private String displayName;
    private String email;
    private String avatar;
    private String role;
    private String provider;
    private String loginMethod;
    private String accessToken; // Keycloak token forwarded from oauth2-service

    public ProfileRequest() {}

    public String getUsername()    { return username; }
    public void setUsername(String v) { this.username = v; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String v) { this.displayName = v; }
    public String getEmail()       { return email; }
    public void setEmail(String v) { this.email = v; }
    public String getAvatar()      { return avatar; }
    public void setAvatar(String v) { this.avatar = v; }
    public String getRole()        { return role; }
    public void setRole(String v) { this.role = v; }
    public String getProvider()    { return provider; }
    public void setProvider(String v) { this.provider = v; }
    public String getLoginMethod() { return loginMethod; }
    public void setLoginMethod(String v) { this.loginMethod = v; }
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String v) { this.accessToken = v; }
}
