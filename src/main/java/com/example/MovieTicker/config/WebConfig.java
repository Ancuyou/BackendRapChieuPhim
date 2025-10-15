package com.example.MovieTicker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;

@Configuration
public class WebConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Chỉ định rõ nguồn gốc của frontend được phép truy cập
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));

        // Các phương thức được phép (GET, POST, etc.)
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // Các header được phép gửi lên
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));

        // Cho phép gửi cookie và các thông tin xác thực
        configuration.setAllowCredentials(true);

        // Thời gian pre-flight request được cache lại (giây)
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Áp dụng cấu hình này cho tất cả các API bắt đầu bằng "/api/"
        source.registerCorsConfiguration("/api/**", configuration);

        return source;
    }
}