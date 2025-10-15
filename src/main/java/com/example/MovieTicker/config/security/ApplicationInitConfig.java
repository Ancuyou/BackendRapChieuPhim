package com.example.MovieTicker.config.security;

import com.example.MovieTicker.entity.TaiKhoan;
import com.example.MovieTicker.entity.User;
import com.example.MovieTicker.entity.VaiTro;
import com.example.MovieTicker.repository.TaiKhoanRepository;
import com.example.MovieTicker.repository.UserRepository;
import com.example.MovieTicker.repository.VaiTroRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.util.Optional;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationInitConfig {

    private final PasswordEncoder passwordEncoder;

    @Bean
    ApplicationRunner applicationRunner(VaiTroRepository vaiTroRepository, UserRepository userRepository, TaiKhoanRepository taiKhoanRepository) {
        return args -> {
            if (vaiTroRepository.findByTenVaiTro("USER").isEmpty()) {
                VaiTro userRole = new VaiTro();
                userRole.setTenVaiTro("USER");
                vaiTroRepository.save(userRole);
                log.info("Created USER role");
            }

            if (vaiTroRepository.findByTenVaiTro("ADMIN").isEmpty()) {
                VaiTro adminRole = new VaiTro();
                adminRole.setTenVaiTro("ADMIN");
                vaiTroRepository.save(adminRole);
                log.info("Created ADMIN role");
            }

            if (!taiKhoanRepository.existsById("admin")) {
                VaiTro adminRole = vaiTroRepository.findByTenVaiTro("ADMIN").get();

                User adminUser = new User();
                adminUser.setHoTen("Admin");
                adminUser.setEmail("admin@movieticker.com");
                adminUser.setSdt("000000000");
                adminUser.setNgaySinh(LocalDate.of(2000, 1, 1));
                userRepository.save(adminUser);

                TaiKhoan adminAccount = new TaiKhoan();
                adminAccount.setTenDangNhap("admin");
                adminAccount.setMatKhau(passwordEncoder.encode("admin123"));
                adminAccount.setUser(adminUser);
                adminAccount.setVaiTro(adminRole);
                taiKhoanRepository.save(adminAccount);
                log.info("Admin account created: admin/admin123");
            }
        };
    }
}