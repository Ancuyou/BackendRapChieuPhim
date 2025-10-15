package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.Ghe;
import com.example.MovieTicker.entity.LoaiGhe;
import com.example.MovieTicker.entity.PhongChieu;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoaiGheRepository extends JpaRepository<LoaiGhe, String> {
    boolean existsByTenLoaiGhe(String tenLoaiGhe);
    LoaiGhe findByTenLoaiGhe(String tenLoaiGhe);


    @Query("""
      SELECT DISTINCT lg
      FROM LoaiGhe lg
      JOIN FETCH lg.listGhe g
      WHERE g.phongChieu = :phongChieu
    """)
    List<LoaiGhe> findAllByPhongChieu(PhongChieu phongChieu);
    
    @Override
    @NonNull
    Page<LoaiGhe> findAll(@NonNull Pageable pageable);
}
