package com.example.MovieTicker.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.entity.VeKhuyenMai;
import com.example.MovieTicker.entity.VeKhuyenMaiId;

@Repository
public interface VeKhuyenMaiRepository extends JpaRepository<VeKhuyenMai, VeKhuyenMaiId> {
    // Custom query methods can be added here

}
