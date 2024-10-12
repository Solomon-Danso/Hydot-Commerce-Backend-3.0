package com.hydottech.Hydot_commerce_30.Controller;

import com.hydottech.Hydot_commerce_30.Entity.ServerCredentials;
import com.hydottech.Hydot_commerce_30.Global.GlobalConstants;
import com.hydottech.Hydot_commerce_30.Global.GlobalFunctions;
import com.hydottech.Hydot_commerce_30.Service.AuditServiceInterface;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/audit")
public class AuditController {


    @Autowired
    private AuditServiceInterface auditServiceInterface;

    @PostMapping("/AppSetup")
    public ResponseEntity<Map<String, Object>> AppSetup(@ModelAttribute ServerCredentials serverCredentials,
                                                        HttpServletRequest request,
                                                        @RequestParam(value = "apiKey", required = false) String apiKey,
                                                        @RequestParam(value = "apiSecret", required = false) String apiSecret,
                                                        @RequestParam(value = "expireDate", required = false) String expireDate) { // expireDate as String
        Map<String, Object> response = new HashMap<>();

        try {
            // Set the apiHost to the default URL where the application is running

            String apiHost = GlobalFunctions.ApiHostGetter(request);

            // Encrypt the apiKey, apiSecret, and apiHost using AES encryption
            String encryptedApiKey = encrypt(apiKey, GlobalConstants.encryptionKey);
            String encryptedApiSecret = encrypt(apiSecret, GlobalConstants.encryptionKey);
            String encryptedApiHost = encrypt(apiHost, GlobalConstants.encryptionKey);

            // Encrypt the expireDate as a string
            String encryptedExpireDate = encrypt(expireDate, GlobalConstants.encryptionKey); // Encrypt the date string directly

            // Check if there are existing credentials
            ServerCredentials existingCredentials = auditServiceInterface.findExistingCredentials();
            if (existingCredentials != null) {
                // Update only the expireDate of the existing credentials
                existingCredentials.setExpireDate(encryptedExpireDate); // Store the encrypted string directly
                existingCredentials.setApiHost(encryptedApiHost);
                auditServiceInterface.save(existingCredentials);
                response.put(GlobalConstants.Message, "Credentials updated successfully.");
            } else {
                // Set encrypted values back to the serverCredentials and save a new record
                serverCredentials.setApiKey(encryptedApiKey);
                serverCredentials.setApiSecret(encryptedApiSecret);
                serverCredentials.setExpireDate(encryptedExpireDate); // Store the encrypted string directly
                serverCredentials.setApiHost(encryptedApiHost);

                auditServiceInterface.save(serverCredentials);

                response.put(GlobalConstants.Message, "App setup completed successfully.");
            }

            response.put(GlobalConstants.Status, GlobalConstants.Success);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (Exception e) {
            response.put(GlobalConstants.Status, GlobalConstants.Failed);
            response.put(GlobalConstants.Message, "Error during setup: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }





    private String encrypt(String data, String key) throws Exception {
        // Implement AES encryption logic here
        // Use javax.crypto.Cipher and related classes for AES encryption

        // Example implementation
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
        javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return java.util.Base64.getEncoder().encodeToString(encryptedData);
    }


    @GetMapping("/GetAppSetup")
    public ResponseEntity<Map<String, Object>> getAppSetup() {
        Map<String, Object> response = new HashMap<>();

        try {
            // Retrieve existing ServerCredentials
            ServerCredentials serverCredentials = auditServiceInterface.findExistingCredentials();

            if (serverCredentials != null) {
                // Decrypt the stored fields
                String decryptedApiKey = decrypt(serverCredentials.getApiKey(), GlobalConstants.encryptionKey);
                String decryptedApiSecret = decrypt(serverCredentials.getApiSecret(), GlobalConstants.encryptionKey);
                String decryptedExpireDate = decrypt(serverCredentials.getExpireDate(), GlobalConstants.encryptionKey);
                String decryptedApiHost = decrypt(serverCredentials.getApiHost(), GlobalConstants.encryptionKey);

                // Convert decryptedExpireDate string to a Date object
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                Date expireDate = dateFormat.parse(decryptedExpireDate);

                // Build response with decrypted values
                response.put("apiKey", decryptedApiKey);
                response.put("apiSecret", decryptedApiSecret);
                response.put("expireDate", dateFormat.format(expireDate)); // Return as a formatted string
                response.put("apiHost", decryptedApiHost);

                response.put(GlobalConstants.Status, GlobalConstants.Success);
                response.put(GlobalConstants.Message, "Data retrieved successfully.");
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                response.put(GlobalConstants.Message, "No credentials found.");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            response.put(GlobalConstants.Status, GlobalConstants.Failed);
            response.put(GlobalConstants.Message, "Error retrieving data: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private String decrypt(String encryptedData, String key) throws Exception {
        // Implement AES decryption logic here
        // Use javax.crypto.Cipher and related classes for AES decryption

        // Example implementation
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
        javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);

        byte[] decodedData = java.util.Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }








}
