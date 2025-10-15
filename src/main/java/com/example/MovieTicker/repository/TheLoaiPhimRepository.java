package com.example.MovieTicker.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.entity.TheLoaiPhim;
@Repository
public interface TheLoaiPhimRepository extends JpaRepository<TheLoaiPhim, String> {
    public boolean existsByTenTheLoai(String tenTheLoai);
}
