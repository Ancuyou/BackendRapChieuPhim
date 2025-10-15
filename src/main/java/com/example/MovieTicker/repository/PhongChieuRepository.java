package com.example.MovieTicker.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;

import com.example.MovieTicker.entity.PhongChieu;

public interface PhongChieuRepository extends JpaRepository<PhongChieu, String> {
	boolean existsByTenPhong(String tenPhong);
	
	@Override
	@NonNull
	Page<PhongChieu> findAll(@NonNull Pageable pageable);
}
