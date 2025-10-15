package com.example.MovieTicker.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import com.example.MovieTicker.repository.TheLoaiPhimRepository;
import com.example.MovieTicker.entity.TheLoaiPhim;

@Repository
public class TheLoaiPhimService {

    @Autowired
    private TheLoaiPhimRepository theLoaiPhimRepository;

    public Page<TheLoaiPhim> getAllTheLoaiPhim(Pageable pageable) {
        return theLoaiPhimRepository.findAll(pageable);
    }

    public List<TheLoaiPhim> getAllTheLoaiPhim() {
        return theLoaiPhimRepository.findAll();
    }

    public TheLoaiPhim getTheLoaiPhimById(String id) {
        return theLoaiPhimRepository.findById(id).orElse(null);
    }

    public TheLoaiPhim createTheLoaiPhim(TheLoaiPhim theLoaiPhim) {
        return theLoaiPhimRepository.save(theLoaiPhim);
    }

    public TheLoaiPhim updateTheLoaiPhim(String id, TheLoaiPhim theLoaiPhim) {
        if (theLoaiPhimRepository.existsById(id)) {
            theLoaiPhim.setMaTheLoai(id);
            return theLoaiPhimRepository.save(theLoaiPhim);
        }
        return null;
    }

    public boolean deleteTheLoaiPhim(String id) {
        if (theLoaiPhimRepository.existsById(id)) {
            theLoaiPhimRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public boolean existsByTenTheLoai(String tenTheLoai) {
        return theLoaiPhimRepository.existsByTenTheLoai(tenTheLoai);
    }

    public Optional<TheLoaiPhim> findByTenPhim(String tenTheLoai) {
        return theLoaiPhimRepository.findAll().stream()
                .filter(theLoaiPhim -> theLoaiPhim.getTenTheLoai().equalsIgnoreCase(tenTheLoai))
                .findFirst();
    }
}
