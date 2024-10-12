package com.hydottech.Hydot_commerce_30.Config;

import com.hydottech.Hydot_commerce_30.Entity.CustomInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private CustomInterceptor customInterceptor;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Map the URL pattern /uploads/** to the new upload directory on the file system
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations("file:/Users/glydetek/Desktop/HydotTech/Products/HES/HES_Backend/Uploads/");
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(customInterceptor)
                .addPathPatterns("/api/**")  // Apply to all routes under /api/audit
                .excludePathPatterns("/api/audit/AppSetup"); // Exclude the AppSetup route
    }
}
