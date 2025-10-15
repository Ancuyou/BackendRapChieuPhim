package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.PendingRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PendingRegistrationRepository extends JpaRepository<PendingRegistration, Long> {

    Optional<PendingRegistration> findByEmail(String email);

    void deleteByExpiryDateBefore(LocalDateTime now);

    boolean existsByEmail(String email);

    boolean existsByTenDangNhap(String tenDangNhap);
}
