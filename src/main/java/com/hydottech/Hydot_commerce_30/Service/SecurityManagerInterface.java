package com.hydottech.Hydot_commerce_30.Service;

import com.hydottech.Hydot_commerce_30.Entity.SecurityManager;

public interface SecurityManagerInterface {

    SecurityManager findSessionByUserId(String userId);

    void saveSession(SecurityManager existingSession);
}
