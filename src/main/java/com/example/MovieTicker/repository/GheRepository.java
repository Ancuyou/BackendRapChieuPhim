package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.Ghe;
import com.example.MovieTicker.entity.PhongChieu;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GheRepository extends JpaRepository<Ghe, String> {
    boolean existsByTenGhe(String tenGhe);

    boolean existsByTenGheAndPhongChieu(String tenGhe, PhongChieu phongChieu);

    List<Ghe> findAllByPhongChieu(PhongChieu phongChieu);

    @Override
    @NonNull
    Page<Ghe> findAll(@NonNull Pageable pageable);
}
