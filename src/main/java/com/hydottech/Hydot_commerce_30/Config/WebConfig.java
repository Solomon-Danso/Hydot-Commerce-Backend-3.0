package com.hydottech.Hydot_commerce_30.Config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Map the URL pattern /uploads/** to the new upload directory on the file system
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations("file:/Users/glydetek/Desktop/HydotTech/Products/HES/HES_Backend/Uploads/");
    }
}
