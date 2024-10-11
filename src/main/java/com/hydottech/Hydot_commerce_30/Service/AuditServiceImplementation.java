package com.hydottech.Hydot_commerce_30.Service;

import com.hydottech.Hydot_commerce_30.Entity.ServerCredentials;
import com.hydottech.Hydot_commerce_30.Repository.AuditServiceRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuditServiceImplementation implements  AuditServiceInterface{

   @Autowired
   private AuditServiceRepo auditServiceRepo;




    @Override
    public ServerCredentials findExistingCredentials() {
        return auditServiceRepo.findTopByOrderByIdAsc();
    }

    @Override
    public ServerCredentials save(ServerCredentials serverCredentials) {
        return auditServiceRepo.save(serverCredentials);
    }
}
