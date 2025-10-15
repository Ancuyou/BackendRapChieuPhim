package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.TaiKhoan;
import com.example.MovieTicker.entity.User;
import com.example.MovieTicker.entity.VaiTro;
import com.example.MovieTicker.exception.AppException;
import com.example.MovieTicker.exception.ErrorCode;
import com.example.MovieTicker.repository.TaiKhoanRepository;
import com.example.MovieTicker.repository.UserRepository;
import com.example.MovieTicker.repository.VaiTroRepository;
import com.example.MovieTicker.request.RegistrationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TaiKhoanService {

    private final TaiKhoanRepository taiKhoanRepository;
    private final UserRepository userRepository;
    private final VaiTroRepository vaiTroRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegistrationRequest request) {
        if (taiKhoanRepository.existsById(request.getTenDangNhap())) {
            throw new AppException(ErrorCode.USER_EXISTS);
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AppException(ErrorCode.EMAIL_EXISTS);
        }

        User user = new User();
        user.setHoTen(request.getHoTen());
        user.setEmail(request.getEmail());
        user.setSdt(request.getSdt());
        user.setNgaySinh(request.getNgaySinh());
        User savedUser = userRepository.save(user);

        VaiTro userRole = vaiTroRepository.findByTenVaiTro("USER")
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));

        TaiKhoan taiKhoan = new TaiKhoan();
        taiKhoan.setTenDangNhap(request.getTenDangNhap());
        taiKhoan.setMatKhau(passwordEncoder.encode(request.getMatKhau()));
        taiKhoan.setUser(savedUser);
        taiKhoan.setVaiTro(userRole);

        taiKhoanRepository.save(taiKhoan);
    }
}