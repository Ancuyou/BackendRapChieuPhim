package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.ChiTietDichVuVe;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ChiTietDichVuVeRepository extends JpaRepository<ChiTietDichVuVe, Long> {
    List<ChiTietDichVuVe> findByVeMaVe(String maVe);
}
