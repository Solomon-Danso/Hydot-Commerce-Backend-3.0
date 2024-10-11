package com.hydottech.Hydot_commerce_30.Service;

import com.hydottech.Hydot_commerce_30.Entity.SecurityManager;
import com.hydottech.Hydot_commerce_30.Entity.Users;
import com.hydottech.Hydot_commerce_30.Repository.SecurityManagerRepo;
import com.hydottech.Hydot_commerce_30.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImplementation implements  UserServiceInterface{

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private SecurityManagerRepo securityRepo;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Users registerUser(Users users) {
        return userRepo.save(users);
    }

    @Override
    public boolean UserIdExists(String generatedUserId) {
        return userRepo.existsByUserId(generatedUserId);  // Ensure this references the correct camelCase field
    }

    @Override
    public Users getUserById(String userId) {
        return userRepo.findByUserId(userId).orElse(null); // Use the new method to find by userId
    }

    @Override
    public Users updateUser(Users existingUser) {
       return userRepo.save(existingUser); // Save the updated user details back to the database
    }

    @Override
    public List<Users> getAllUsers() {
        return userRepo.findAll(); // Retrieve all users from the database
    }

    @Override
    public void deleteUser(String userId) {
        userRepo.deleteByUserId(userId); // Delete the user by userId
    }

    @Override
    public boolean superAdminExists() {
        return userRepo.existsByPrimaryRole("SuperAdmin");
    }


    @Override
    public boolean checkPassword(Users user, String password) {
        // Compare the raw password with the hashed password stored in the database
        return passwordEncoder.matches(password, user.getPassword());
    }



    @Override
    public List<Users> findByEmail(String email) {
        return userRepo.findByEmail(email);
    }


    ;



}
