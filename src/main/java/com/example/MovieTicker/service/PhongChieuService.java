package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.repository.PhongChieuRepository;
import com.example.MovieTicker.request.PhongChieuRequest;
import jakarta.annotation.PostConstruct;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class PhongChieuService {
    @Autowired
    private PhongChieuRepository phongChieuRepository;

    @PostConstruct
    public void seedPhongChieu() {
        String[] defaultPhong = {"Phòng 1", "Phòng 2", "Phòng VIP"};
        for (String ten : defaultPhong) {
            if (!phongChieuRepository.existsByTenPhong(ten)) {
                PhongChieu pc = PhongChieu.builder().tenPhong(ten).build();
                phongChieuRepository.save(pc);
            }
        }
    }

    public List<PhongChieu> getListPhongChieu() {
        return phongChieuRepository.findAll();
    }
    
    public Page<PhongChieu> getPhongChieuPage(Pageable pageable) {
        return phongChieuRepository.findAll(pageable);
    }
    
    public PhongChieu getPhongChieuById(String id) {
        Optional<PhongChieu> phongChieuOptional = phongChieuRepository.findById(id);
        return phongChieuOptional.orElse(null);
    }
    
    public PhongChieu createPhongChieu(PhongChieuRequest request) {
        PhongChieu phongChieu = new PhongChieu();
        phongChieu.setTenPhong(request.getTenPhong());
        phongChieu.setSoLuongGhe(request.getSoLuongGhe());
        
        return phongChieuRepository.save(phongChieu);
    }
    
    public PhongChieu updatePhongChieu(String id, PhongChieuRequest request) {
        Optional<PhongChieu> phongChieuOptional = phongChieuRepository.findById(id);
        
        if (phongChieuOptional.isPresent()) {
            PhongChieu phongChieu = phongChieuOptional.get();
            phongChieu.setTenPhong(request.getTenPhong());
            phongChieu.setSoLuongGhe(request.getSoLuongGhe());
            
            return phongChieuRepository.save(phongChieu);
        }
        
        return null;
    }
    
    public boolean deletePhongChieu(String id) {
        Optional<PhongChieu> phongChieuOptional = phongChieuRepository.findById(id);
        
        if (phongChieuOptional.isPresent()) {
            phongChieuRepository.delete(phongChieuOptional.get());
            return true;
        }
        
        return false;
    }
}
