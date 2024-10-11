package com.hydottech.Hydot_commerce_30.Service;

import com.hydottech.Hydot_commerce_30.Entity.SecurityManager;
import com.hydottech.Hydot_commerce_30.Entity.Users;

import java.util.List;

public interface UserServiceInterface {
    Users registerUser(Users users);

    boolean UserIdExists(String generatedUserId);

    Users getUserById(String userId);

    Users updateUser(Users existingUser);

    List<Users> getAllUsers();

    void deleteUser(String userId);


    boolean superAdminExists();

    boolean checkPassword(Users user, String password);


    List<Users> findByEmail(String email);
}
