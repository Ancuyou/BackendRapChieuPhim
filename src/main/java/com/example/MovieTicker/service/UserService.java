package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.TaiKhoan;
import com.example.MovieTicker.entity.User;
import com.example.MovieTicker.repository.TaiKhoanRepository;
import com.example.MovieTicker.request.UserRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    @Autowired
    TaiKhoanRepository taiKhoanRepository;

    public void deleteById(String integer) {
        taiKhoanRepository.deleteById(integer);
    }

    public Page<TaiKhoan> findAll(Pageable pageable) {
        return taiKhoanRepository.findAll(pageable);
    }

    public long count() {
        return taiKhoanRepository.count();
    }

    public boolean existsById(String integer) {
        return taiKhoanRepository.existsById(integer);
    }

    public Optional<TaiKhoan> search_TaiKhoan(String hoTen, String sdt) {
        return taiKhoanRepository.findByUser_HoTenOrUser_Sdt(hoTen, sdt);
    }

    public <S extends TaiKhoan> S save(S entity) {
        return taiKhoanRepository.save(entity);
    }

    public Optional<TaiKhoan> findById(String integer) {
        return taiKhoanRepository.findById(integer);
    }
}
