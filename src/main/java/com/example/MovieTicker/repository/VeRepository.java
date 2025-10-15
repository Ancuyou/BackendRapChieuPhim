package com.example.MovieTicker.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.MovieTicker.entity.Ve;
import com.example.MovieTicker.enums.TicketStatus;

public interface VeRepository extends JpaRepository<Ve, String> {
    List<Ve> findBySuatChieuMaSuatChieuAndGheMaGheIn(String maSc, List<String> maGheList);
    
    @Query("SELECT v FROM Ve v WHERE v.suatChieu.maSuatChieu = :maSuatChieu")
    List<Ve> findBySuatChieuMaSuatChieu(@Param("maSuatChieu") String maSuatChieu);
    
    @Query("SELECT v FROM Ve v WHERE v.suatChieu.maSuatChieu = :maSuatChieu AND v.ghe.maGhe IN :maGheList AND v.trangThai = :trangThai")
    List<Ve> findTicketsBySuatChieuAndSeatsAndStatus(@Param("maSuatChieu") String maSuatChieu, @Param("maGheList") List<String> maGheList, @Param("trangThai") String trangThai);
    
    @Query("SELECT v FROM Ve v WHERE v.suatChieu.maSuatChieu = :maSuatChieu AND v.ghe.maGhe IN :maGheList AND v.trangThai = :trangThai AND v.ngayDat < :expiredTime")
    List<Ve> findTicketsBySuatChieuAndSeatsAndStatusAndTime(@Param("maSuatChieu") String maSuatChieu, @Param("maGheList") List<String> maGheList, @Param("trangThai") String trangThai, @Param("expiredTime") LocalDateTime expiredTime);
    
    // Legacy methods - deprecated, use status-based methods above
    @Deprecated
    @Query("SELECT v FROM Ve v WHERE v.suatChieu.maSuatChieu = :maSuatChieu AND v.ghe.maGhe IN :maGheList AND v.trangThai = 'PAID'")
    List<Ve> findPaidTicketsBySuatChieuAndSeats(@Param("maSuatChieu") String maSuatChieu, @Param("maGheList") List<String> maGheList);
    
    @Deprecated
    @Query("SELECT v FROM Ve v WHERE v.suatChieu.maSuatChieu = :maSuatChieu AND v.ghe.maGhe IN :maGheList AND v.trangThai = 'PROCESSING' AND v.ngayDat < :expiredTime")
    List<Ve> findExpiredProcessingTickets(@Param("maSuatChieu") String maSuatChieu, @Param("maGheList") List<String> maGheList, @Param("expiredTime") LocalDateTime expiredTime);
}
