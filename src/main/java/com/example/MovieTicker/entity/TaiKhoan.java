package com.example.MovieTicker.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "TaiKhoan")
public class TaiKhoan {
    @Id
    private String TenDangNhap;
    
    private String MatKhau;


    
    @ManyToOne
    @JoinColumn(name = "maUser", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "vaiTroID", nullable = false)
    private VaiTro vaiTro;

}
