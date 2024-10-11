package com.hydottech.Hydot_commerce_30.Repository;


import com.hydottech.Hydot_commerce_30.Entity.SecurityManager;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecurityManagerRepo extends JpaRepository<SecurityManager, Long> {
    SecurityManager findByUserId(String userId);
}
