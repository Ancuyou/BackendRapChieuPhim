package com.example.MovieTicker.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "pending_registrations")
public class PendingRegistration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String tenDangNhap;

    @Column(nullable = false)
    private String matKhau; // Mật khẩu đã được mã hóa

    @Column(nullable = false)
    private String hoTen;

    @Column(nullable = false, unique = true)
    private String email;

    private String sdt;

    private LocalDate ngaySinh;

    @Column(nullable = false)
    private LocalDateTime expiryDate; // Thời gian hết hạn
}
