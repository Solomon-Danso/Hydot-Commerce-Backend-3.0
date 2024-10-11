package com.hydottech.Hydot_commerce_30.DTOs;

import java.time.LocalDateTime;

public class UserDTO {
    private String userId;
    private String picture;
    private String fullName;
    private String email;
    private String phoneNumber;
    private boolean isBlocked;
    private boolean isPasswordReset;
    private String primaryRole;
    private LocalDateTime dateCreated;

    // Constructors, Getters, and Setters
    public UserDTO(String userId, String picture, String fullName, String email, String phoneNumber,
                   boolean isBlocked, boolean isPasswordReset, String primaryRole, LocalDateTime dateCreated) {
        this.userId = userId;
        this.picture = picture;
        this.fullName = fullName;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.isBlocked = isBlocked;
        this.isPasswordReset = isPasswordReset;
        this.primaryRole = primaryRole;
        this.dateCreated = dateCreated;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public boolean isBlocked() {
        return isBlocked;
    }

    public void setBlocked(boolean blocked) {
        isBlocked = blocked;
    }

    public boolean isPasswordReset() {
        return isPasswordReset;
    }

    public void setPasswordReset(boolean passwordReset) {
        isPasswordReset = passwordReset;
    }

    public String getPrimaryRole() {
        return primaryRole;
    }

    public void setPrimaryRole(String primaryRole) {
        this.primaryRole = primaryRole;
    }

    public LocalDateTime getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(LocalDateTime dateCreated) {
        this.dateCreated = dateCreated;
    }


// Getters and setters (you can generate these using your IDE)
}
