package com.example.MovieTicker.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.MovieTicker.entity.KhuyenMai;

public interface KhuyenMaiRepository extends JpaRepository<KhuyenMai, String>   {
    @Query("SELECT k FROM KhuyenMai k WHERE k.ngayBatDau <= :currentDate AND k.ngayKetThuc >= :currentDate")
    List<KhuyenMai> findValidPromotions(@Param("currentDate") LocalDate currentDate);

    @Query("SELECT k FROM KhuyenMai k WHERE k.tenKm LIKE %:keyword% OR k.moTa LIKE %:keyword%")
    List<KhuyenMai> findByKeyword(@Param("keyword") String keyword);

    // Page<KhuyenMai> findKhuyenMaisByTenKmContainingIgnoreCaseAndMaCodeContainingIgnoreCase(String keyword, Pageable pageable);

    Page<KhuyenMai> findAll(Pageable pageable);

    Optional<KhuyenMai> findByMaCode(String maCode);
}
