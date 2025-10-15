package com.example.MovieTicker.response;

import java.time.LocalDate;
import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class KhuyenMaiResponse {
    private String maKm;
    private String tenKm;
    private String moTa;
    private Double giaTri;
    private LocalDate ngayBatDau;
    private LocalDate ngayKetThuc;
    private String maCode;
    private int soLuong;
    private boolean trangThai;
    private String urlHinh;
}

