package com.example.MovieTicker.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class PasswordResetToken { // Ma OTP
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String token;
    @OneToOne(targetEntity = TaiKhoan.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "ten_dang_nhap" )
    private TaiKhoan taiKhoan;
    @Column(nullable = false)
    private LocalDateTime expiryDate;
    public PasswordResetToken(String token, TaiKhoan taiKhoan){
        this.token = token;
        this.taiKhoan = taiKhoan;
        this.expiryDate = LocalDateTime.now().plusMinutes(3); // Token hợp lệ trong 3 phút
    }
}
