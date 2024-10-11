package com.hydottech.Hydot_commerce_30.Repository;


import com.hydottech.Hydot_commerce_30.Entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {
    boolean existsByUserId(String userId);  // Change parameter to camelCase
    Optional<Users> findByUserId(String userId);

    void deleteByUserId(String userId);

    boolean existsByPrimaryRole(String superAdmin);


    @Query("SELECT u FROM Users u WHERE u.email = :email")
    List<Users> findByEmail(@Param("email") String email);
}
