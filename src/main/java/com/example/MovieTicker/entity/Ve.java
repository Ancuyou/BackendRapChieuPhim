package com.example.MovieTicker.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "Ve")
public class Ve {
    @Id
    private String maVe;

    @ManyToOne
    @JoinColumn(name = "maHD", nullable = false)
    private HoaDon hoaDon;

    @ManyToOne
    @JoinColumn(name = "maUser", nullable = true)
    private User user;

    @ManyToOne
    @JoinColumn(name = "maSuatChieu", nullable = false)
    private SuatChieu suatChieu; 
   
    @ManyToOne
    @JoinColumn(name = "maGhe", nullable = false)
    private Ghe ghe; 

    @Column(nullable = false)
    private LocalDateTime ngayDat;

    @Column(nullable = false)
    private Double thanhTien;

    @Column(name = "trang_thai", nullable = false)
    @Builder.Default
    private String trangThai = "PROCESSING";

    @Column(name = "qr_code_url", length = 500)
    private String qrCodeUrl; // Lưu đường dẫn đầy đủ đến file QR code

    // 1 Vé có nhiều ChiTietDichVuVe
    @OneToMany(mappedBy = "ve", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<ChiTietDichVuVe> chiTietDichVuVes;

    @OneToMany(mappedBy = "ve")
    @JsonIgnore
    private List<VeKhuyenMai> khuyenMais;

    @PrePersist
    protected void onCreate() {
        this.ngayDat = LocalDateTime.now();
        if(this.thanhTien == null) {
            this.thanhTien = 0.0;
        }
        if(maVe == null || maVe.isEmpty()) {
            this.maVe = generateMaVe();
        }
        // QR code sẽ được tạo từ QRCodeService sau khi save
    }

    private String generateMaVe() {
        return "VE-" + System.currentTimeMillis() + (int)(Math.random() * 1000);
    }
}
