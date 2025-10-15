package com.example.MovieTicker.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.entity.DanhGiaPhim;

@Repository
public interface DanhGiaPhimRepository extends JpaRepository<DanhGiaPhim, String> {
    List<DanhGiaPhim> findByPhimMaPhim(String maPhim);
    
    @Query("SELECT d FROM DanhGiaPhim d WHERE " +
           "(:tenPhim IS NULL OR :tenPhim = '' OR LOWER(d.phim.tenPhim) LIKE LOWER(CONCAT('%', :tenPhim, '%')))")
    Page<DanhGiaPhim> findByPhimTenPhimContaining(@Param("tenPhim") String tenPhim, Pageable pageable);
}
