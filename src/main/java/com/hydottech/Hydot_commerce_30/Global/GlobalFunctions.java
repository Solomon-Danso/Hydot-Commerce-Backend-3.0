package com.hydottech.Hydot_commerce_30.Global;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Random;
import java.util.UUID;
import java.time.Year;

public class GlobalFunctions {


    public static String saveFile(MultipartFile file) {
        String uploadDirectory = "/Users/glydetek/Desktop/HydotTech/Products/HES/HES_Backend/Uploads/"; // Ensure there's a trailing slash
        String originalFilename = file.getOriginalFilename();

        if (originalFilename == null) {
            throw new IllegalArgumentException("File name cannot be null");
        }

        // Extract the file extension from the original file name
        String fileExtension = "";
        int dotIndex = originalFilename.lastIndexOf('.');
        if (dotIndex >= 0) {
            fileExtension = originalFilename.substring(dotIndex);
        }

        // Add a UUID to the file name to avoid collisions, and append the file extension
        String uniqueFileName = UUID.randomUUID().toString() + fileExtension;

        File uploadDir = new File(uploadDirectory);

        // Ensure the upload directory exists
        if (!uploadDir.exists()) {
            boolean created = uploadDir.mkdirs(); // Creates the directory and any necessary parent directories
            if (!created) {
                throw new RuntimeException("Failed to create upload directory: " + uploadDirectory);
            }
        }

        File destinationFile = new File(uploadDir, uniqueFileName); // Create the destination file in the upload directory

        try {
            file.transferTo(destinationFile); // Save the file
        } catch (IOException e) {
            e.printStackTrace(); // Consider using a logging framework
            throw new RuntimeException("Failed to save file: " + e.getMessage(), e);
        }

        // Return the unique file name
        return uniqueFileName;
    }


    public static String IdGenerator(String institutionCode) {
        // Get the current year and take the last 2 digits
        String year = String.valueOf(Year.now().getValue()).substring(2);

        // Generate a random 3-digit number
        Random random = new Random();
        String randomDigits = String.format("%04d", random.nextInt(9999));

        // Combine institution code, year, and random digits
        return institutionCode + year + randomDigits;
    }

    public static String PasswordGenerator() {
        Random random = new Random();
        String randomDigits = String.format("%08d", random.nextInt(99999999));
        return  randomDigits;
    }

    public static String ApiHostGetter(HttpServletRequest request) {
        String apiHost = "";
        try {
            String fullUrl = request.getRequestURL().toString();
            java.net.URL url = new java.net.URL(fullUrl);
            apiHost = url.getProtocol() + "://" + url.getHost();

            // Append the port only if it's not the default port
            if ((url.getPort() != -1) && (url.getPort() != 80 && url.getPort() != 443)) {
                apiHost += ":" + url.getPort();
            }
        } catch (java.net.MalformedURLException e) {
            // Handle the exception, you can log the error message or take appropriate action
            System.err.println("Error parsing URL: " + e.getMessage());
        }
        return apiHost;
    }








}
