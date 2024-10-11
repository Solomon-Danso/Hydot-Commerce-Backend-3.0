package com.hydottech.Hydot_commerce_30.Controller;

import com.hydottech.Hydot_commerce_30.DTOs.UserDTO;
import com.hydottech.Hydot_commerce_30.Entity.Users;
import com.hydottech.Hydot_commerce_30.Global.GlobalConstants;
import com.hydottech.Hydot_commerce_30.Global.GlobalFunctions;
import com.hydottech.Hydot_commerce_30.Service.EmailService;
import com.hydottech.Hydot_commerce_30.Service.UserServiceInterface;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UsersController {
    @Autowired
    private UserServiceInterface userServiceInterface;

    @Autowired
    private EmailService emailService; // Inject EmailService here

    @Autowired
    private BCryptPasswordEncoder passwordEncoder; // Inject BCryptPasswordEncoder



    @GetMapping("/")
    public String Test(){
    return "Let Start The Hydot Commerce System";
}


    @PostMapping("/SetupRegisterUser")
    public ResponseEntity<Map<String, Object>> SetupRegisterUser(@ModelAttribute Users users,
                                                                 @RequestParam(value = "userPic", required = false) MultipartFile picture) {
        Map<String, Object> response = new HashMap<>();

        // Check if a SuperAdmin already exists
        boolean superAdminExists = userServiceInterface.superAdminExists();
        if (superAdminExists) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "A SuperAdmin already exists. Cannot create another SuperAdmin.");
            return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
        }

        // Handle the picture if provided
        if (picture != null && !picture.isEmpty()) {
            String fileName = GlobalFunctions.saveFile(picture);
            users.setPicture(fileName);
        }

        String generatedUserId;
        String rawPassword = GlobalFunctions.PasswordGenerator(); // Generate a password

        do {
            generatedUserId = GlobalFunctions.IdGenerator(GlobalConstants.InstitutionCode);
        } while (userServiceInterface.UserIdExists(generatedUserId));

        users.setUserId(generatedUserId);
        users.setPasswordReset(false);
        users.setPrimaryRole(GlobalConstants.SuperAdmin);

        String encodedPassword = passwordEncoder.encode(rawPassword);
        users.setPassword(encodedPassword);

        if (users.getEmail() == null  || users.getEmail().isEmpty() ) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "Email cannot be empty");
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }

        userServiceInterface.registerUser(users);



        // Send welcome email
        try {
            emailService.sendWelcomeEmail(users.getEmail(), users.getFullName(), rawPassword); // Use the injected service here
        } catch (MessagingException e) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User Created but failed to send email");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        response.put("status", GlobalConstants.Success);
        response.put("message", "SuperAdmin Created Successfully");
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }


    @PostMapping("/RegisterUser")
    public ResponseEntity<Map<String, Object>> registerUser(@ModelAttribute Users users,
                                                            @RequestParam(value = "userPic", required = false) MultipartFile picture) {
        Map<String, Object> response = new HashMap<>();

        if (picture != null && !picture.isEmpty()) {
            String fileName = GlobalFunctions.saveFile(picture);
            users.setPicture(fileName);
        }

        String generatedUserId;
        String rawPassword = GlobalFunctions.PasswordGenerator(); // Create a method for this

        do {
            generatedUserId = GlobalFunctions.IdGenerator(GlobalConstants.InstitutionCode);
        } while (userServiceInterface.UserIdExists(generatedUserId));

        users.setUserId(generatedUserId);

        users.setPasswordReset(false);


        String encodedPassword = passwordEncoder.encode(rawPassword);
        users.setPassword(encodedPassword);

        userServiceInterface.registerUser(users);

        // Send welcome email
        try {
            emailService.sendWelcomeEmail(users.getEmail(), users.getFullName(), rawPassword); // Use the injected service here


        } catch (MessagingException e) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User Created but failed to send email");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        response.put("status", GlobalConstants.Success);
        response.put("message", "User Created Successfully");

        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/UpdateUser")
    public ResponseEntity<Map<String, Object>> updateUser(@RequestParam("userId") String userId,
                                                          @ModelAttribute Users updatedUser,
                                                          @RequestParam(value = "userPic", required = false) MultipartFile picture,
                                                          @RequestParam(value = "newPassword", required = false) String newPassword) {
        Map<String, Object> response = new HashMap<>();

        // Check if the user exists
        Users existingUser = userServiceInterface.getUserById(userId);
        if (existingUser == null) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User not found");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        // Update user's picture if a new one is provided
        if (picture != null && !picture.isEmpty()) {
            String fileName = GlobalFunctions.saveFile(picture);
            existingUser.setPicture(fileName);
        }

        // Update user details based on the form data
        existingUser.setFullName(updatedUser.getFullName() != null ? updatedUser.getFullName() : existingUser.getFullName());
        existingUser.setEmail(updatedUser.getEmail() != null ? updatedUser.getEmail() : existingUser.getEmail());
        existingUser.setPhoneNumber(updatedUser.getPhoneNumber() != null ? updatedUser.getPhoneNumber() : existingUser.getPhoneNumber());

        // Update password if a new password is provided
        if (newPassword != null && !newPassword.isEmpty()) {
            String encodedPassword = passwordEncoder.encode(newPassword);
            existingUser.setPassword(encodedPassword);
        }

        // Save the updated user details
        userServiceInterface.updateUser(existingUser);

        response.put("status", GlobalConstants.Success);
        response.put("message", "User details updated successfully");

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/AllUsers")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<Users> usersList = userServiceInterface.getAllUsers();

        if (usersList.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT); // Return 204 if no users are found
        }

        // Convert Users entities to UserDTO to exclude sensitive fields like password and token
        List<UserDTO> userDTOList = usersList.stream()
                .map(user -> new UserDTO(
                        user.getUserId(),
                        user.getPicture(),
                        user.getFullName(),
                        user.getEmail(),
                        user.getPhoneNumber(),
                        user.isBlocked(),
                        user.isPasswordReset(),
                        user.getPrimaryRole(),
                        user.getDateCreated()
                ))
                .toList();

        return new ResponseEntity<>(userDTOList, HttpStatus.OK);
    }


    @PostMapping("/GetUser")
    public ResponseEntity<Map<String, Object>> getUserById(@RequestParam("userId") String userId) {
        Map<String, Object> response = new HashMap<>();
        Users user = userServiceInterface.getUserById(userId);

        if (user == null) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User not found");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        response.put("status", GlobalConstants.Success);
        response.put("user", user);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/DeleteUser")
    public ResponseEntity<Map<String, Object>> deleteUser(@RequestParam("userId") String userId) {
        Map<String, Object> response = new HashMap<>();

        Users user = userServiceInterface.getUserById(userId);
        if (user == null) {
            response.put("status", GlobalConstants.Failed);
            response.put("message", "User not found");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        userServiceInterface.deleteUser(userId);
        response.put("status", GlobalConstants.Success);
        response.put("message", "User deleted successfully");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }





}
