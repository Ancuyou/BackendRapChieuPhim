package com.example.MovieTicker.entity;

import java.time.LocalDate;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "ve_khuyen_mai")
@Data
public class VeKhuyenMai {
    @EmbeddedId
    private VeKhuyenMaiId id;

    @ManyToOne
    @MapsId("maVe")  // Tên phải trùng với tên field trong VeKhuyenMaiId
    @JoinColumn(name = "ma_ve")  // Sửa thành "ma_ve" chữ thường
    private Ve ve;

    @ManyToOne
    @MapsId("maKm")  // Tên phải trùng với tên field trong VeKhuyenMaiId
    @JoinColumn(name = "ma_km")  // Đảm bảo đúng tên cột trong database
    private KhuyenMai khuyenMai;

    @Column(name = "ngay_ap_dung")
    private LocalDate ngayApDung;
}
