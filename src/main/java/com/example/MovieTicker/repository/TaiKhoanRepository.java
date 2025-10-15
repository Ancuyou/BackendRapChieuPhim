package com.example.MovieTicker.repository;

import com.example.MovieTicker.entity.TaiKhoan;
import com.example.MovieTicker.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TaiKhoanRepository extends JpaRepository<TaiKhoan,String> {
    Optional<TaiKhoan> findByUser_HoTenOrUser_Sdt(String hoTen, String sdt);
    Optional<TaiKhoan> findByUser(User user);
}
