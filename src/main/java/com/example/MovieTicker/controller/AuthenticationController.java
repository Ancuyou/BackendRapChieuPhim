package com.example.MovieTicker.controller;

import com.example.MovieTicker.request.*;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.response.AuthenticateResponse;
import com.example.MovieTicker.response.IntrospectResponse;
import com.example.MovieTicker.service.AuthenticateService;
import com.example.MovieTicker.service.TaiKhoanService;
import com.nimbusds.jose.JOSEException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticateService authenticateService;
    private final TaiKhoanService taiKhoanService;

    @PostMapping("/login")
    public ApiResponse<AuthenticateResponse> login(@RequestBody AuthenticateRequest request) {
        var result = authenticateService.authenticated(request);
        return ApiResponse.<AuthenticateResponse>builder()
                .message("Authentication successful")
                .data(result)
                .build();
    }

//    @PostMapping("/register")
//    public ApiResponse<Void> register(@RequestBody @Valid RegistrationRequest request) {
//        taiKhoanService.register(request);
//        return ApiResponse.<Void>builder()
//                .code(201)
//                .message("User registered successfully")
//                .build();
//    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@RequestBody LogoutRequest request) throws JOSEException, ParseException {
        authenticateService.logout(request);
        return ApiResponse.<Void>builder()
                .message("Logout successful")
                .build();
    }

    @PostMapping("/introspect")
    public ApiResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        var result = authenticateService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder().data(result).build();
    }
    @PostMapping("/refresh")
    public ApiResponse<AuthenticateResponse> refreshToken(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        var result = authenticateService.refreshToken(request);
        return ApiResponse.<AuthenticateResponse>builder()
                .data(result)
                .build();
    }
    @PostMapping("/forgot-password")
    public ApiResponse<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        authenticateService.forgotPassword(request);
        return ApiResponse.<String>builder()
                .message("OTP has been sent to your email.")
                .build();
    }

    @PostMapping("/reset-password")
    public ApiResponse<String> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authenticateService.resetPassword(request);
        return ApiResponse.<String>builder()
                .message("Password has been reset successfully.")
                .build();
    }

    @PostMapping("/register")
    public ApiResponse<String> register(@RequestBody @Valid RegistrationRequest request) {
        authenticateService.register(request);
        return ApiResponse.<String>builder()
                .code(201)
                .message("Mã OTP đã được gửi đến email của bạn. Vui lòng xác thực để hoàn tất đăng ký.")
                .data(request.getEmail()) // Trả về email để frontend biết cần xác thực tài khoản nào
                .build();
    }

    @PostMapping("/verify-otp")
    public ApiResponse<Void> verifyOtp(@RequestBody @Valid VerifyOtpRequest request) {
        authenticateService.verifyOtp(request);
        return ApiResponse.<Void>builder()
                .code(200)
                .message("Xác thực OTP thành công. Tài khoản đã được kích hoạt.")
                .build();
    }

    @PostMapping("/resend-otp")
    public ApiResponse<String> resendOtp(@RequestBody @Valid ResendOtpRequest request) {
        authenticateService.resendOtp(request);
        return ApiResponse.<String>builder()
                .code(200)
                .message("Một mã OTP mới đã được gửi đến email của bạn.")
                .data(request.getEmail())
                .build();
    }


}
