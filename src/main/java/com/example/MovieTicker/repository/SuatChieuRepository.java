package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.Phim;
import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.entity.SuatChieu;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

@Repository
public interface SuatChieuRepository extends JpaRepository<SuatChieu, String> {
    public boolean existsByPhimAndPhongChieuAndThoiGianBatDau(Phim phim, PhongChieu phongChieu, LocalDateTime thoiGianBatDau);
    public SuatChieu findByPhongChieuAndThoiGianBatDau(PhongChieu phongChieu, LocalDateTime thoiGianBatDau);
    List<SuatChieu> findByPhongChieu(PhongChieu phongChieu);


    @Override
    @NonNull
    Page<SuatChieu> findAll(@NonNull Pageable pageable);
}
