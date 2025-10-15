package com.example.MovieTicker.service;

import java.util.List;
import java.util.Optional;

import com.example.MovieTicker.entity.LoaiGhe;
import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.repository.LoaiGheRepository;
import com.example.MovieTicker.repository.GheRepository;
import com.example.MovieTicker.request.LoaiGheRequest;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class LoaiGheService {
    @Autowired
    private LoaiGheRepository loaiGheRepository;
    @Autowired
    private GheRepository gheRepository;

    @PostConstruct
    public void seedLoaiGhe() {
        String[] defaultTypes = {"Thường", "VIP", "Couple"};
        for (String ten : defaultTypes) {
            if (!loaiGheRepository.existsByTenLoaiGhe(ten)) {
                LoaiGhe lg = LoaiGhe.builder().tenLoaiGhe(ten)
                .build();
                if(ten.equals("VIP")){
                    float phuthu = 20000f;
                    lg.setPhuThu(phuthu);
                } else if(ten.equals("Couple")){
                    float phuthu = 40000f;
                    lg.setPhuThu(phuthu);
                } else{
                    lg.setPhuThu(0f);
                }
                loaiGheRepository.save(lg);
            }
        }
    }

    public List<LoaiGhe> getAllLoaiGhe() {
        return loaiGheRepository.findAll();
    }

    public List<LoaiGhe> getAllLoaiGheByPhongChieu(PhongChieu phongChieu) {
        return loaiGheRepository.findAllByPhongChieu(phongChieu);
    }


    public LoaiGhe getLoaiGheById(String id) {
        Optional<LoaiGhe> loaiGheOptional = loaiGheRepository.findById(id);
        return loaiGheOptional.orElse(null);
    }
    
    public LoaiGhe createLoaiGhe(LoaiGheRequest request) {
        LoaiGhe loaiGhe = new LoaiGhe();
        if(loaiGheRepository.existsByTenLoaiGhe(request.getTenLoaiGhe())){
            throw new RuntimeException("Loại ghế với tên '" + request.getTenLoaiGhe() + "' đã tồn tại");
        }
        loaiGhe.setTenLoaiGhe(request.getTenLoaiGhe());
        loaiGhe.setPhuThu(request.getPhuThu());
        
        return loaiGheRepository.save(loaiGhe);
    }
    
    public LoaiGhe updateLoaiGhe(String id, LoaiGheRequest request) {
        Optional<LoaiGhe> loaiGheOptional = loaiGheRepository.findById(id);
        
        if (loaiGheOptional.isPresent()) {
            LoaiGhe loaiGhe = loaiGheOptional.get();
            loaiGhe.setTenLoaiGhe(request.getTenLoaiGhe());
            loaiGhe.setPhuThu(request.getPhuThu());
            
            return loaiGheRepository.save(loaiGhe);
        }
        
        return null;
    }
    
    public boolean deleteLoaiGhe(String id) {
        Optional<LoaiGhe> loaiGheOptional = loaiGheRepository.findById(id);
        
        if (loaiGheOptional.isPresent()) {
            loaiGheRepository.delete(loaiGheOptional.get());
            return true;
        }
        
        return false;
    }
}
