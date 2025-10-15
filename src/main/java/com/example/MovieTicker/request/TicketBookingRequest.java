package com.example.MovieTicker.request;

import java.util.List;

import lombok.Data;

@Data
public class TicketBookingRequest {
    private String maPhim; 
    private String maSuatChieu;
    private String maPhong;
    private List<String> maGheList; 
    private String maKhuyenMai; 
    private List<DichVuRequest> dichVuList;
    private String phuongThucThanhToan;
}
