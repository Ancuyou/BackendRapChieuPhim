package com.example.MovieTicker.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class SuatChieu {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maSuatChieu;

    private int donGiaCoSo;

    @Column(nullable = false)
    private LocalDateTime thoiGianBatDau;

    @ManyToOne
    @JoinColumn(name = "MaPhim")
    private Phim phim;

    @ManyToOne
    @JoinColumn(name = "MaPhongChieu")
    private PhongChieu phongChieu;
}
