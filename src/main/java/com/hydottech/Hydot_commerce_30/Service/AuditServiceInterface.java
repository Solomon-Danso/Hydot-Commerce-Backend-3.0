package com.hydottech.Hydot_commerce_30.Service;

import com.hydottech.Hydot_commerce_30.Entity.ServerCredentials;

public interface AuditServiceInterface {
   
    ServerCredentials findExistingCredentials();

    ServerCredentials save(ServerCredentials serverCredentials);
}
