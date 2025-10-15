package com.example.MovieTicker.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Phim {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maPhim;
    @Column(unique = true, nullable = false, length = 255)
    private String tenPhim;
    @Column(length = 1000)
    private String moTa;
    @Column(length = 255)
    private String daoDien;
    @Column(length = 500)
    private String dienVien;
    private int thoiLuong;
    private LocalDate ngayKhoiChieu;
    @Column(length = 500)
    private String hinhAnh;
    @Column(length = 500)
    private String trailerURL;
    private int tuoi;
    @Column(length = 255)
    private String trangThai;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.MERGE)
    @JoinTable(
        name = "phim_the_loai",
        joinColumns = @JoinColumn(name = "maPhim"), 
        inverseJoinColumns = @JoinColumn(name = "maTheLoai")
    )
    private List<TheLoaiPhim> listTheLoai = new ArrayList<>();

    @OneToMany(mappedBy = "phim", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnoreProperties({"phim"})
    private List<SuatChieu> listSuatChieu = new ArrayList<>();

    @OneToMany(mappedBy = "phim", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<DanhGiaPhim> danhGiaPhims = new ArrayList<>();

    
}
