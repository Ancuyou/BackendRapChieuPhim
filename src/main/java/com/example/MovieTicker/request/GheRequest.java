package com.example.MovieTicker.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GheRequest {
    private String tenGhe;
    private String maPhongChieu;
    private String maLoaiGhe;
}