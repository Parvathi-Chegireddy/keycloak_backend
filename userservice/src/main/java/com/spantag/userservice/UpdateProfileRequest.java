package com.spantag.userservice;

public class UpdateProfileRequest {

    private String email;
    private String displayName;
    private String avatarUrl;

    public UpdateProfileRequest() {}

    public String getEmail()                  { return email; }
    public void setEmail(String email)        { this.email = email; }

    public String getDisplayName()                    { return displayName; }
    public void setDisplayName(String displayName)    { this.displayName = displayName; }

    public String getAvatarUrl()                  { return avatarUrl; }
    public void setAvatarUrl(String avatarUrl)    { this.avatarUrl = avatarUrl; }
}