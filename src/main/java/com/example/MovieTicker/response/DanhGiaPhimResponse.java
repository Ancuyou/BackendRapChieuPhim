package com.example.MovieTicker.response;

import java.time.LocalDate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DanhGiaPhimResponse {
    private String id;
    private Double rating;
    private String comment;
    private String userName;
    private String fullName;
    private String userEmail;
    private String maPhim;
    private String tenPhim;
    private LocalDate createdAt;
}
