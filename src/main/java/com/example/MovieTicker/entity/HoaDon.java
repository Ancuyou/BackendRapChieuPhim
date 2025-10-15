package com.example.MovieTicker.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "HoaDon")
public class HoaDon {

    @Id
    private String maHD;

    @ManyToOne
    @JoinColumn(name = "ma_user", nullable = true)
    private User user;

    private LocalDateTime ngayLap;

    @Column(nullable = false)
    private Double tongTien;

    private String phuongThucThanhToan;

    private String trangThai;

    @Column(nullable = false)
    private String maGiaoDich;

    private String ghiChu;

    private String transactionNo;
    private String transactionDate;
    private String responseCode;

    @JsonIgnore
    @OneToMany(mappedBy = "hoaDon", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Ve> ves;

    @PrePersist
    protected void onCreate() {
        ngayLap = LocalDateTime.now();
        if (trangThai == null) {
            trangThai = "PENDING";
        }
        if(maHD == null) {
            maHD = "HD" + System.currentTimeMillis() + (int)(Math.random() * 1000);
        }
    }
}
