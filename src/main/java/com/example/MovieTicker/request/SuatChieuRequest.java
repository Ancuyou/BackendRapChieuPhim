package com.example.MovieTicker.request;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class SuatChieuRequest {
    private int donGiaCoSo;
    private LocalDateTime thoiGianBatDau;
    private String maPhim;
    private String maPhongChieu;
}
