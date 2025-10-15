package com.example.MovieTicker.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoaiGheRequest {
    private String tenLoaiGhe;
    private float phuThu;
}