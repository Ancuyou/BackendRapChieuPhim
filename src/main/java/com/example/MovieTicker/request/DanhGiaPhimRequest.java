package com.example.MovieTicker.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DanhGiaPhimRequest {
    
    @NotNull(message = "Rating không được để trống")
    @Min(value = 0, message = "Rating phải từ 0 đến 5")
    @Max(value = 5, message = "Rating phải từ 0 đến 5")
    private Double rating;
    
    @NotBlank(message = "Comment không được để trống")
    private String comment;
    
    @NotBlank(message = "Mã phim không được để trống")
    private String maPhim;
}
