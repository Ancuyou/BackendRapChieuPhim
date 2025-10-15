package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.SuatChieu;
import com.example.MovieTicker.entity.Phim;
import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.repository.SuatChieuRepository;
import com.example.MovieTicker.repository.PhimRepository;
import com.example.MovieTicker.repository.PhongChieuRepository;
import com.example.MovieTicker.request.SuatChieuRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class SuatChieuService {
    @Autowired
    private SuatChieuRepository suatChieuRepository;
    @Autowired
    private PhimRepository phimRepository;
    @Autowired
    private PhongChieuRepository phongChieuRepository;

    public SuatChieu createSuatChieu(SuatChieuRequest request) {
        String maPhim = request.getMaPhim();
        Phim phim = phimRepository.findById(request.getMaPhim())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phim: " + maPhim));
        PhongChieu phongChieu = phongChieuRepository.findById(request.getMaPhongChieu())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phòng chiếu"));

        // Thời gian bắt đầu và kết thúc (bao gồm thời gian dọn dẹp)
        LocalDateTime batDauMoi = request.getThoiGianBatDau();
        LocalDateTime ketThucMoi = batDauMoi.plusMinutes(phim.getThoiLuong()).plusHours(1); // +1 tiếng dọn dẹp

        // Lấy tất cả suất chiếu cùng phòng
        List<SuatChieu> suatChieuCungPhong = suatChieuRepository.findByPhongChieu(phongChieu);
        // Kiểm tra giao nhau
        for (SuatChieu sc : suatChieuCungPhong) {
            LocalDateTime batDauCu = sc.getThoiGianBatDau();
            LocalDateTime ketThucCu = batDauCu.plusMinutes(sc.getPhim().getThoiLuong()).plusHours(1); // +1 tiếng dọn dẹp

            // Nếu khoảng thời gian giao nhau thì báo lỗi
            boolean isOverlap = !(ketThucMoi.isBefore(batDauCu) || batDauMoi.isAfter(ketThucCu));
            if (isOverlap) {
                throw new RuntimeException("Suất chiếu bị giao nhau với suất chiếu khác trong cùng phòng (bao gồm thời gian dọn dẹp)! Phim: " + sc.getPhim().getTenPhim());
            }
        }

        SuatChieu suatChieu = SuatChieu.builder()
                .phim(phim)
                .phongChieu(phongChieu)
                .thoiGianBatDau(request.getThoiGianBatDau())
                .donGiaCoSo(request.getDonGiaCoSo())
                .build();
        return suatChieuRepository.save(suatChieu);
    }

    public List<SuatChieu> getAllSuatChieu() {
        return suatChieuRepository.findAll();
    }

    
    public Page<SuatChieu> getSuatChieuPage(Pageable pageable) {
        return suatChieuRepository.findAll(pageable);
    }

    public SuatChieu getSuatChieuById(String id) {
        return suatChieuRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy suất chiếu"));
    }

    public SuatChieu updateSuatChieu(String id, SuatChieuRequest request) {
        SuatChieu suatChieu = getSuatChieuById(id);
        Phim phim = phimRepository.findById(request.getMaPhim())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phim"));
        PhongChieu phongChieu = phongChieuRepository.findById(request.getMaPhongChieu())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phòng chiếu"));
        suatChieu.setDonGiaCoSo(request.getDonGiaCoSo());
        suatChieu.setThoiGianBatDau(request.getThoiGianBatDau());
        suatChieu.setPhim(phim);
        suatChieu.setPhongChieu(phongChieu);
        return suatChieuRepository.save(suatChieu);
    }

    public void deleteSuatChieu(String id) {
        SuatChieu suatChieu = getSuatChieuById(id);
        suatChieuRepository.delete(suatChieu);
    }
}
