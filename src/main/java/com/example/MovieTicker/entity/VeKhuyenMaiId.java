package com.example.MovieTicker.entity;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

@Embeddable
@Data
@AllArgsConstructor
@NoArgsConstructor
public class VeKhuyenMaiId implements Serializable {
    @Column(name = "ma_ve")  // Sửa thành "ma_ve" chữ thường để khớp với database
    private String maVe;
    
    @Column(name = "ma_km")  // Đảm bảo đúng tên cột trong database
    private String maKm;
}