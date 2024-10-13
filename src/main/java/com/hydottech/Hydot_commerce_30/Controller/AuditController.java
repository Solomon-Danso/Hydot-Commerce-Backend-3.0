package com.hydottech.Hydot_commerce_30.Controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hydottech.Hydot_commerce_30.Entity.ServerCredentials;
import com.hydottech.Hydot_commerce_30.Global.GlobalConstants;
import com.hydottech.Hydot_commerce_30.Global.GlobalFunctions;
import com.hydottech.Hydot_commerce_30.Service.AuditServiceInterface;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final Logger logger = LoggerFactory.getLogger(AuditController.class);


    @Autowired
    private AuditServiceInterface auditServiceInterface;

    @Autowired
    private RestTemplate restTemplate;





    @PostMapping("/AppSetup")
    public ResponseEntity<Map<String, Object>> AppSetup(@ModelAttribute ServerCredentials serverCredentials,
                                                        HttpServletRequest request,
                                                        @RequestParam(value = "apiHost", required = false) String apiHost,
                                                        @RequestParam(value = "apiKey", required = false) String apiKey,
                                                        @RequestParam(value = "apiSecret", required = false) String apiSecret,
                                                        @RequestParam(value = "email", required = false) String email,
                                                        @RequestParam(value = "companyName", required = false) String companyName,
                                                        @RequestParam(value = "companyId", required = false) String companyId,
                                                        @RequestParam(value = "companyPhone", required = false) String companyPhone,
                                                        @RequestParam(value = "productId", required = false) String productId,
                                                        @RequestParam(value = "packageType", required = false) String packageType,
                                                        @RequestParam(value = "softwareID", required = false) String softwareID,
                                                        @RequestParam(value = "expireDate", required = false) String expireDate) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Check the Origin or Referer header to ensure request comes from the allowed URL
            String originHeader = request.getHeader("Origin");
            String refererHeader = request.getHeader("Referer");
            String allowedOrigin = "https://adminpanel.hydottech.com";
            //String allowedOrigin = "http://localhost:3000";


            if (!allowedOrigin.equals(originHeader) && !allowedOrigin.equals(refererHeader)) {
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                response.put(GlobalConstants.Message, "Unauthorized request source");
                return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
            }

            // Encrypt and process the data as you have done before
            String encryptedApiHost = encrypt(apiHost, GlobalConstants.encryptionKey);
            String encryptedApiKey = encrypt(apiKey, GlobalConstants.encryptionKey);
            String encryptedApiSecret = encrypt(apiSecret, GlobalConstants.encryptionKey);
            String encryptedEmail = encrypt(email, GlobalConstants.encryptionKey);
            String encryptedCompanyName = encrypt(companyName, GlobalConstants.encryptionKey);
            String encryptedCompanyId = encrypt(companyId, GlobalConstants.encryptionKey);
            String encryptedCompanyPhone = encrypt(companyPhone, GlobalConstants.encryptionKey);
            String encryptedProductId = encrypt(productId, GlobalConstants.encryptionKey);
            String encryptedPackageType = encrypt(packageType, GlobalConstants.encryptionKey);
            String encryptedSoftwareID = encrypt(softwareID, GlobalConstants.encryptionKey);

            // Check if there are existing credentials
            ServerCredentials existingCredentials = auditServiceInterface.findExistingCredentials();
            if (existingCredentials != null) {
                existingCredentials.setApiHost(encryptedApiHost);
                auditServiceInterface.save(existingCredentials);
                response.put(GlobalConstants.Message, "Credentials updated successfully.");
            } else {
                serverCredentials.setApiKey(encryptedApiKey);
                serverCredentials.setApiSecret(encryptedApiSecret);
                serverCredentials.setApiHost(encryptedApiHost);
                serverCredentials.setEmail(encryptedEmail);
                serverCredentials.setCompanyName(encryptedCompanyName);
                serverCredentials.setCompanyId(encryptedCompanyId);
                serverCredentials.setCompanyPhone(encryptedCompanyPhone);
                serverCredentials.setProductId(encryptedProductId);
                serverCredentials.setPackageType(encryptedPackageType);
                serverCredentials.setSoftwareID(encryptedSoftwareID);

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



    @PostMapping("/TopUp")
    public ResponseEntity<Map<String, Object>> TopUp(
                                                        HttpServletRequest request,
                                                        @RequestParam(value = "apiHost", required = false) String apiHost,
                                                        @RequestParam(value = "companyId", required = false) String companyId,
                                                        @RequestParam(value = "productId", required = false) String productId,
                                                        @RequestParam(value = "packageType", required = false) String packageType,
                                                        @RequestParam(value = "softwareID", required = false) String softwareID,
                                                        @RequestParam(value = "expireDate", required = false) String expireDate) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Check the Origin or Referer header to ensure request comes from the allowed URL
            String originHeader = request.getHeader("Origin");
            String refererHeader = request.getHeader("Referer");
            // String allowedOrigin = "https://mainapi.hydottech.com";
            String allowedOrigin = "http://localhost:8000";


            if (!allowedOrigin.equals(originHeader) && !allowedOrigin.equals(refererHeader)) {
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                response.put("originHeader",originHeader);
                response.put("refererHeader",refererHeader);
                response.put(GlobalConstants.Message, "Unauthorized request source");
                return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
            }



            ServerCredentials serverCredential = auditServiceInterface.findExistingCredentials();
            if(serverCredential==null){
                response.put(GlobalConstants.Message, "Configure your application before you proceed.");
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }


            String decryptedApiHost = decrypt(serverCredential.getApiHost(), GlobalConstants.encryptionKey);
            String decryptedCompanyId = decrypt(serverCredential.getCompanyId(), GlobalConstants.encryptionKey);
            String decryptedProductId = decrypt(serverCredential.getProductId(), GlobalConstants.encryptionKey);
            String decryptedPackageType = decrypt(serverCredential.getPackageType(), GlobalConstants.encryptionKey);
            String decryptedSoftwareID = decrypt(serverCredential.getSoftwareID(), GlobalConstants.encryptionKey);

            if(!decryptedApiHost.equals(apiHost)){
                response.put(GlobalConstants.Message, "Invalid Api Host");
                response.put("ConfigData",decryptedApiHost);
                response.put("ResponseData",apiHost);
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            if(!decryptedCompanyId.equals(companyId)){
                response.put(GlobalConstants.Message, "Invalid Company ID");
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            if(!decryptedProductId.equals(productId)){
                response.put(GlobalConstants.Message, "Invalid Product ID");
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            if(!decryptedPackageType.equals(packageType)){
                response.put(GlobalConstants.Message, "Invalid Package Type");
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            if(!decryptedSoftwareID.equals(softwareID)){
                response.put(GlobalConstants.Message, "Invalid Software ID");
                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            // Encrypt and process the data as you have done before
            String encryptedExpireDate = encrypt(expireDate, GlobalConstants.encryptionKey);
            serverCredential.setExpireDate(encryptedExpireDate);
            auditServiceInterface.save(serverCredential);
            response.put(GlobalConstants.Message, "Subscription was successful, Enjoy using your software.");
            response.put(GlobalConstants.Status, GlobalConstants.Success);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (Exception e) {
            response.put(GlobalConstants.Status, GlobalConstants.Failed);
            response.put(GlobalConstants.Message, "Error during setup: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }





    @PostMapping("/subscriptionPayment")
    public ResponseEntity<Map<String, Object>> topUp(
            HttpServletRequest request,
            @RequestParam(value = "amount", required = false) String amount) {

        Map<String, Object> response = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            logger.info("Starting subscription payment process for amount: {}", amount);

            // Fetch the server credentials
            ServerCredentials serverCredential = auditServiceInterface.findExistingCredentials();
            if (serverCredential == null) {
                logger.error("Server credentials not found. Please configure your application before proceeding.");
                response.put("message", "Configure your application before you proceed.");
                response.put("status", "failed");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Decrypt the Software ID from the server credentials
            String decryptedSoftwareID = decrypt(serverCredential.getSoftwareID(), GlobalConstants.encryptionKey);
            String decryptedCompanyEmail = decrypt(serverCredential.getEmail(), GlobalConstants.encryptionKey);

            // Send a GET request to the external API using RestTemplate
            String externalApiUrl = "https://mainapi.hydottech.com/api/HCSSchedulePayment/" + decryptedSoftwareID + "/" + amount;
            logger.info("Sending request to external API: {}", externalApiUrl);

            ResponseEntity<String> externalApiResponse = restTemplate.exchange(
                    externalApiUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(new HttpHeaders()),
                    String.class
            );



            String message = externalApiResponse.getBody();



            // Handle the response from the external API
            if (externalApiResponse.getStatusCode() == HttpStatus.OK) {
                 response.put(GlobalConstants.Status, GlobalConstants.Success);
                response.put(GlobalConstants.Message, "Please check your email "+decryptedCompanyEmail+" to approve this transaction.");
                return new ResponseEntity<>(response, HttpStatus.CREATED);
            } else {


                response.put(GlobalConstants.Status, GlobalConstants.Failed);
                response.put(GlobalConstants.Message, message);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            response.put(GlobalConstants.Status, GlobalConstants.Failed);
            response.put(GlobalConstants.Message, e.getMessage());
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



    @PostMapping("/Decrypt")
    public ResponseEntity<Map<String, Object>> Decrypter(
            @RequestParam(value = "dataField", required = false) String dataField) {

        Map<String, Object> response = new HashMap<>();

        String decrypted = decrypt2(dataField, GlobalConstants.encryptionKey);
        response.put(GlobalConstants.Status, GlobalConstants.Success);
        response.put(GlobalConstants.Message, decrypted);
        return new ResponseEntity<>(response, HttpStatus.CREATED);


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

    private String decrypt2(String encryptedData, String key) {
        try {
            // Initialize the AES cipher for decryption
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);

            // Decode and decrypt the data
            byte[] decodedData = java.util.Base64.getDecoder().decode(encryptedData);
            byte[] decryptedData = cipher.doFinal(decodedData);

            return new String(decryptedData);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Decryption error: No such algorithm found", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Decryption error: No such padding found", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Decryption error: Invalid key", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Decryption error: Problem with block size or padding", e);
        }
    }









}
