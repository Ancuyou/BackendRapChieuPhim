package com.example.MovieTicker.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class HoaDonResponse {
    private String maHD;
    private LocalDateTime ngayLap;
    private Double tongTien;
    private Double tongTienVe;
    private Double tongTienDichVu;
    private String phuongThucThanhToan;
    private String trangThai;
    private String maGiaoDich;
    private String transactionNo;
    private String transactionDate;
    private String responseCode;
    private String ghiChu;
    private List<VeResponse> danhSachVe;
    private List<DichVuResponse> danhSachDichVu;
    private String tenNguoiDung;
    private String emailNguoiDung;
    private String soDienThoai;
    private Integer soLuongVe;
    private LocalDateTime expiredAt;
    private Boolean isExpired;
}