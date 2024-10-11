package com.hydottech.Hydot_commerce_30.Entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import lombok.Data;

import java.util.Date;

@Entity
@Data
public class ServerCredentials {
    @jakarta.persistence.Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;
    private String apiHost;
    private String apiKey;
    private String apiSecret;
    private String expireDate;
    private String checkSum;


}
