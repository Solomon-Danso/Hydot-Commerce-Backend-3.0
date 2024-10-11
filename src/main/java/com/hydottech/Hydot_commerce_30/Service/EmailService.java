package com.hydottech.Hydot_commerce_30.Service;

import jakarta.mail.internet.MimeMessage;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private SpringTemplateEngine templateEngine;

    public void sendWelcomeEmail(String to, String userName, String rawPassword) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        // Set mail attributes
        helper.setTo(to);
        helper.setSubject("Welcome to HydotTech!");
        helper.setFrom("customers@hydottech.com");

        // Prepare the context with variables
        Context context = new Context();
        context.setVariable("userName", userName);
        context.setVariable("userEmail", to);
        context.setVariable("rawPassword", rawPassword);
        context.setVariable("appName", "HydotTech");
        context.setVariable("year", String.valueOf(java.time.Year.now()));

        // Load the HTML template
        String htmlContent = templateEngine.process("welcome-email", context);
        helper.setText(htmlContent, true);  // Set to true to enable HTML content

        // Send the email
        mailSender.send(message);
    }

//    public void sendLoginTokenEmail(String email, String token) {
//    }


    public void sendLoginTokenEmail(String to, String token) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        // Set mail attributes
        helper.setTo(to);
        helper.setSubject("Authentication");
        helper.setFrom("customers@hydottech.com");

        // Prepare the context with variables
        Context context = new Context();
        context.setVariable("token", token);
        context.setVariable("appName", "HydotTech");
        context.setVariable("year", String.valueOf(java.time.Year.now()));

        // Load the HTML template
        String htmlContent = templateEngine.process("loginEmail", context);
        helper.setText(htmlContent, true);  // Set to true to enable HTML content

        // Send the email
        mailSender.send(message);
    }




}
