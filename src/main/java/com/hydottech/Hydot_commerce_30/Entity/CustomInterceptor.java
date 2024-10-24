package com.hydottech.Hydot_commerce_30.Entity;

import com.hydottech.Hydot_commerce_30.Global.GlobalConstants;
import com.hydottech.Hydot_commerce_30.Service.AuditServiceInterface;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class CustomInterceptor implements HandlerInterceptor {

    @Autowired
    private AuditServiceInterface auditServiceInterface;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestUri = request.getRequestURI();
        if ("/api/audit/AppSetup".equals(requestUri)) {
            return true; // Allow access to /AppSetup without checks
        }

        ServerCredentials serverCredentials = auditServiceInterface.findExistingCredentials();
        if (serverCredentials == null) {
            return sendJsonErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "No credentials found. Please set up the application first.");
        }

        String decryptedApiKey = decrypt(serverCredentials.getApiKey(), GlobalConstants.encryptionKey);
        String decryptedApiHost = decrypt(serverCredentials.getApiHost(), GlobalConstants.encryptionKey);
        String decryptedExpireDate = decrypt(serverCredentials.getExpireDate(), GlobalConstants.encryptionKey);

        String requestHost = ApiHostGetter(request);

        if (!decryptedApiHost.equals(requestHost)) {
            return sendJsonErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Unauthorized access: You are not allowed to use this app.");

        }

        String providedApiKey = request.getHeader("apiKey");
        if (providedApiKey == null || !providedApiKey.equals(decryptedApiKey)) {
            return sendJsonErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized access: Invalid API key.");
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        Date expireDate = dateFormat.parse(decryptedExpireDate);

// Add 1 day to the expireDate
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(expireDate);
        calendar.add(Calendar.DAY_OF_MONTH, 1);
        expireDate = calendar.getTime();

// Check if the current date is after the updated expireDate
        if (new Date().after(expireDate)) {
            return sendJsonErrorResponse(response, HttpServletResponse.SC_PAYMENT_REQUIRED, "Subscription expired: Please renew your subscription.");
        }



        return true; // Allow the request to proceed
    }

    private boolean sendJsonErrorResponse(HttpServletResponse response, int statusCode, String message) throws Exception {
        Map<String, Object> jsonResponse = new HashMap<>();
        jsonResponse.put(GlobalConstants.Status, GlobalConstants.Failed);
        jsonResponse.put(GlobalConstants.Message, message);

        response.setStatus(statusCode);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponseString = objectMapper.writeValueAsString(jsonResponse);
        response.getWriter().write(jsonResponseString);

        return false;
    }

    private String decrypt(String data, String key) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
        javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedData = java.util.Base64.getDecoder().decode(data);
        return new String(cipher.doFinal(decryptedData));
    }

    private String ApiHostGetter(HttpServletRequest request) {
        try {
            String fullUrl = request.getRequestURL().toString();
            java.net.URL url = new java.net.URL(fullUrl);
            String apiHost = url.getProtocol() + "://" + url.getHost();
            if (url.getPort() != -1 && (url.getPort() != 80 && url.getPort() != 443)) {
                apiHost += ":" + url.getPort();
            }
            String finalApihost = apiHost+"/";
            return finalApihost;
        } catch (java.net.MalformedURLException e) {
            return null;
        }
    }
}
