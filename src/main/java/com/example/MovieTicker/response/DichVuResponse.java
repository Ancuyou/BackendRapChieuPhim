package com.example.MovieTicker.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DichVuResponse {
    private String maDichVu;
    private String tenDichVu;
    private Double giaDichVu;
    private Integer soLuong;
    private Double thanhTien;
    private String moTa;
}