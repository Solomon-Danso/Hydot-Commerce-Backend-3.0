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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
           // String allowedOrigin = "https://adminpanel.hydottech.com";
            String allowedOrigin = "http://localhost:3000";


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
            response.put(GlobalConstants.Message, "ExpireDate updated successfully.");
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



    @PostMapping("/Decrypt")
    public ResponseEntity<Map<String, Object>> Decrypter(
            @RequestParam(value = "dataField", required = false) String dataField) {

        Map<String, Object> response = new HashMap<>();

        String decrypted = decrypt2(dataField, GlobalConstants.encryptionKey);
        response.put(GlobalConstants.Status, GlobalConstants.Success);
        response.put(GlobalConstants.Message, decrypted);
        return new ResponseEntity<>(response, HttpStatus.CREATED);


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
