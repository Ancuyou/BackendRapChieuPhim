package com.example.MovieTicker.request;

import java.time.LocalDate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PhimRequest {
    private String tenPhim;
    private String moTa;
    private String daoDien;
    private String dienVien;
    private int thoiLuong;
    private LocalDate ngayKhoiChieu;
    private String hinhAnh;
    private String trailerURL;
    private int tuoi;
    private String trangThai;
    private String[] theLoai;
}