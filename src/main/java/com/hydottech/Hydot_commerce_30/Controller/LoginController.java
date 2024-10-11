package com.hydottech.Hydot_commerce_30.Controller;

import com.hydottech.Hydot_commerce_30.Entity.Users;
import com.hydottech.Hydot_commerce_30.Entity.SecurityManager;
import com.hydottech.Hydot_commerce_30.Global.GlobalConstants;
import com.hydottech.Hydot_commerce_30.Service.SecurityManagerInterface;
import com.hydottech.Hydot_commerce_30.Service.UserServiceInterface;
import com.hydottech.Hydot_commerce_30.Service.EmailService;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class LoginController {

    @Autowired
    private UserServiceInterface userServiceInterface;

    @Autowired
    private SecurityManagerInterface securityManagerInterface;

    @Autowired
    private EmailService emailService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String email, @RequestParam String password) {
        Map<String, Object> response = new HashMap<>();

        // Find user by email
        List<Users> users = userServiceInterface.findByEmail(email);
        if (users.isEmpty()) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User not found.");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        Users user = users.get(0); // Get the first user or implement your logic

        // Check if the account is blocked
        if (user.isBlocked()) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "Your account is blocked. Please contact support.");
            return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
        }

        // Check if the password is correct
        if (!userServiceInterface.checkPassword(user, password)) {
            user.incrementFailedLoginAttempts(); // Increment failed login attempts
            userServiceInterface.updateUser(user);

            // Check if the user has exceeded the allowed number of failed attempts
            if (user.getFailedLoginAttempts() >= 3) {
                user.setBlocked(true); // Block the user
                userServiceInterface.updateUser(user); // Update the user in the database
                response.put("status", GlobalConstants.Failed);
                response.put("message", "Your account has been blocked due to multiple failed login attempts.");
                return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
            }

            // Inform the user about the incorrect password attempt
            response.put("status", GlobalConstants.Failed);
            response.put("message", "Incorrect password. Attempt " + user.getFailedLoginAttempts() + " of 3.");
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }

        // Reset failed login attempts after a successful password check
        user.resetFailedLoginAttempts();
        user.generateToken(); // Generate a new login token
        userServiceInterface.updateUser(user); // Update the user with the new token

        // Send the login token to the user's email
        try {
            emailService.sendLoginTokenEmail(user.getEmail(), user.getToken()); // Use the injected service here
        } catch (MessagingException e) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "Failed to send email. Please try again later.");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        response.put("status", GlobalConstants.Success);
        response.put("email", user.getEmail());
        response.put("userId", user.getUserId());
        response.put("message", "Login token has been sent to " + user.getEmail());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }










    @PostMapping("/verifyToken")
    public ResponseEntity<Map<String, Object>> verifyToken(@RequestParam String userId, @RequestParam String token) {
        Map<String, Object> response = new HashMap<>();
        Users user = userServiceInterface.getUserById(userId);

        if (user == null) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User not found.");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        if (!user.getToken().equals(token) || user.isTokenExpired()) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "Invalid or expired token.");
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }

        // Generate a new session ID
        String sessionId = UUID.randomUUID().toString();
        SecurityManager existingSession = securityManagerInterface.findSessionByUserId(userId);

        if (existingSession != null) {
            existingSession.setSessionId(sessionId); // Replace existing session ID with a new one
        } else {
            existingSession = new SecurityManager(userId, sessionId);
        }

        securityManagerInterface.saveSession(existingSession);

        response.put("status", GlobalConstants.Success);
        response.put("fullName", user.getFullName());
        response.put("userId", user.getUserId());
        response.put("sessionId", sessionId);
        response.put("picture", user.getPicture());
        response.put("email", user.getEmail());
        response.put("primaryRole", user.getPrimaryRole());

        return new ResponseEntity<>(response, HttpStatus.OK);
    }



}
