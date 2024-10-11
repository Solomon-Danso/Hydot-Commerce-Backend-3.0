package com.hydottech.Hydot_commerce_30.Repository;

import com.hydottech.Hydot_commerce_30.Entity.ServerCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditServiceRepo extends JpaRepository<ServerCredentials,Long> {

    ServerCredentials findTopByOrderByIdAsc();
}
