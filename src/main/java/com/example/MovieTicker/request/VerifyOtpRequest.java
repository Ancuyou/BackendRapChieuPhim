package com.example.MovieTicker.request;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VerifyOtpRequest {
    @NotBlank
    private String email;
    @NotBlank
    private String otp;
}
