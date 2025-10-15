package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.PasswordResetToken;
import com.example.MovieTicker.entity.TaiKhoan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken,Long> {
    Optional<PasswordResetToken> findByToken(String token);
    Optional<PasswordResetToken> findByTaiKhoan(TaiKhoan taiKhoan);
}
