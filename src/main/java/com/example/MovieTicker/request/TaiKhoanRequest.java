package com.example.MovieTicker.request;

import com.example.MovieTicker.entity.VaiTro;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TaiKhoanRequest {
    private String TenDangNhap;
    private String MatKhau;
    private UserRequest user;
    private VaiTro vaiTro;
}
