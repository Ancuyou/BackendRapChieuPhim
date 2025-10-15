package com.example.MovieTicker.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Paths;

@Configuration
public class StaticResourceConfig implements WebMvcConfigurer {

    @Value("${qr.code.upload.path:uploads/qr-codes}")
    private String uploadPath;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Cấu hình để serve static files từ thư mục uploads
        String absolutePath = Paths.get(uploadPath).toAbsolutePath().toString();
        
        registry.addResourceHandler("/uploads/qr-codes/**")
                .addResourceLocations("file:" + absolutePath + "/");
    }
}