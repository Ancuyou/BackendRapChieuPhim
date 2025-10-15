package com.example.MovieTicker.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.MovieTicker.entity.HoaDon;
import com.example.MovieTicker.entity.User;

public interface HoaDonRepository extends JpaRepository<HoaDon, String> {
    
    @Query("SELECT h FROM HoaDon h WHERE h.trangThai = :trangThai AND h.ngayLap < :expiredTime")
    List<HoaDon> findExpiredInvoicesByStatus(@Param("trangThai") String trangThai, @Param("expiredTime") LocalDateTime expiredTime);
    
    @Query("SELECT h FROM HoaDon h WHERE h.trangThai = 'PROCESSING' AND h.ngayLap < :expiredTime")
    List<HoaDon> findExpiredProcessingInvoices(@Param("expiredTime") LocalDateTime expiredTime);
    

    List<HoaDon> findByUserOrderByNgayLapDesc(User user);
}
