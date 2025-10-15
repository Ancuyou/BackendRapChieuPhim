package com.example.MovieTicker.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VeResponse {
    private String maVe;
    private String tenPhim;
    private String tenPhongChieu;
    private String tenGhe;
    private String hangGhe;
    private Integer soGhe;
    private String loaiGhe;
    private Double giaGhe;
    private LocalDateTime ngayChieu;
    private LocalDateTime thoiGianChieu;
    private LocalDateTime ngayDat;
    private Double thanhTien;
    private String trangThai;
    private String maHoaDon;
    private String maSuatChieu;
    private String qrCodeUrl; 
}