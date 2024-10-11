package com.hydottech.Hydot_commerce_30.Entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class SecurityManager {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String userId; // Ensure the userId is unique

    private String sessionId;

    public SecurityManager(String userId, String sessionId) {
        this.userId = userId;
        this.sessionId = sessionId;
    }

}
