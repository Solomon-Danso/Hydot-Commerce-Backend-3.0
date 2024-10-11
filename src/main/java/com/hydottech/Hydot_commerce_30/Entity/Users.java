package com.hydottech.Hydot_commerce_30.Entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Entity
@Data
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userId;
    private String picture;
    private String fullName;
    private String email;
    private String phoneNumber;
    private String password;
    private boolean isBlocked;
    private boolean isPasswordReset;
    private String primaryRole;
    private String token;
    private LocalDateTime tokenExpiresIn;

    @CreationTimestamp
    private LocalDateTime dateCreated;

    private int failedLoginAttempts; // Track the number of failed login attempts

    public void generateToken() {
        this.token = String.valueOf((int) (Math.random() * 90000) + 10000); // Generate a 5-digit token
        this.tokenExpiresIn = LocalDateTime.now().plus(10, ChronoUnit.MINUTES); // Token expires in 10 minutes
    }

    public boolean isTokenExpired() {
        return LocalDateTime.now().isAfter(this.tokenExpiresIn);
    }

    // Increment failed login attempts by 1
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
    }

    // Retrieve the number of failed login attempts
    public int getFailedLoginAttempts() {
        return this.failedLoginAttempts;
    }

    // Reset the number of failed login attempts to 0
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }

    // Block the user if they have exceeded the allowed number of failed attempts
    public void checkAndBlockUser(int maxFailedAttempts) {
        if (this.failedLoginAttempts >= maxFailedAttempts) {
            this.isBlocked = true;
        }
    }



}
