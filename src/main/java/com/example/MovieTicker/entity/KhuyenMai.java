package com.example.MovieTicker.entity;

import java.time.LocalDate;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "KhuyenMai")
public class KhuyenMai {
    @Id
    private String maKm;

    @Column(nullable = false)
    private String tenKm;

    @Column(nullable = false)
    private String moTa;

    @Column(nullable = false)
    private Double giaTri; // % giảm

    @Column(nullable = false)
    private LocalDate ngayBatDau;

    @Column(nullable = false)
    private LocalDate ngayKetThuc;

    @Column(nullable = false, unique = true)
    private String maCode; // Mã code khuyến mãi

    @Column(nullable = false)
    private Integer soLuong; // Số lượng mã khuyến mãi có thể sử dụng

    @Column(nullable = false)
    private boolean trangThai;

    private String urlHinh;

    @OneToMany(mappedBy = "khuyenMai")
    private List<VeKhuyenMai> ves;
    
    @PrePersist
    public void prePersist() {
        if (this.maKm == null) {
            this.maKm = generateMaKm();
        }
    }
    
    private String generateMaKm() {
        long timestamp = System.currentTimeMillis();
        int random = (int) (Math.random() * 900) + 100;
        return "KM" + String.valueOf(timestamp).substring(8) + random;
    }
}
