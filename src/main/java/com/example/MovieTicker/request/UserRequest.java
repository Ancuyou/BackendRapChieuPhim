package com.example.MovieTicker.request;

import com.example.MovieTicker.entity.TaiKhoan;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {
    private Long maUser;
    private String hoTen;
    private String email;
    private String sdt;
    private LocalDate ngaySinh;
    private List<TaiKhoan> taiKhoan;
}
