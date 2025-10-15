package com.example.MovieTicker.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.entity.Phim;

@Repository
public interface PhimRepository extends JpaRepository<Phim, String> {
   
    Optional<Phim> findByTenPhim(String tenPhim);
    
    boolean existsByTenPhim(String tenPhim);


    @Query("""
    SELECT DISTINCT p
    FROM Phim p
    LEFT JOIN p.listTheLoai tl
    WHERE LOWER(p.tenPhim) LIKE LOWER(CONCAT('%', :keyword, '%'))
       OR LOWER(p.daoDien) LIKE LOWER(CONCAT('%', :keyword, '%'))
       OR LOWER(tl.tenTheLoai) LIKE LOWER(CONCAT('%', :keyword, '%'))
    """)
    Page<Phim> findByKeyword(@Param("keyword") String keyword, Pageable pageable);


    Page<Phim> findAll(Pageable pageable);
    

}