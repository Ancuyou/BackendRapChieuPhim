package com.example.MovieTicker.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.entity.DichVuDiKem;

@Repository
public interface DichVuDiKemRepository extends JpaRepository<DichVuDiKem, Long> {
    Optional<DichVuDiKem> findById(Long id);
    Page<DichVuDiKem> findAll(Pageable pageable);

    Page<DichVuDiKem> findDichVuDiKemByTenDvContainingIgnoreCaseAndDanhMuc(String tenDv, String danhMuc,
                                                                           Pageable pageable);

    Page<DichVuDiKem> findDichVuDiKemByTenDvContainingIgnoreCase(String tenDv, Pageable pageable);

    List<DichVuDiKem> findByDanhMuc(String tendanhmuc);
}
