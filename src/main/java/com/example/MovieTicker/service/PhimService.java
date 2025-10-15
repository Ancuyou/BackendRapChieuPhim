package com.example.MovieTicker.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.example.MovieTicker.entity.Phim;
import com.example.MovieTicker.entity.TheLoaiPhim;
import com.example.MovieTicker.repository.PhimRepository;
import com.example.MovieTicker.request.PhimRequest;

@Service
public class PhimService {

    @Autowired
    private PhimRepository phimRepository;

    @Autowired
    private TheLoaiPhimService theLoaiPhimService;

    public Phim createPhim(PhimRequest request) {
        if (phimRepository.existsByTenPhim(request.getTenPhim())) {
            throw new RuntimeException("Phim với tên '" + request.getTenPhim() + "' đã tồn tại");
        }
        List<TheLoaiPhim> theLoaiPhimList = new ArrayList<>();
        System.out.println("Thể loại phim: " + request.getTheLoai());
        String[] tenTheLoai = request.getTheLoai();
        System.out.println(tenTheLoai);
        if (tenTheLoai != null) {
            for (String ten : tenTheLoai) {
                if (!theLoaiPhimService.existsByTenTheLoai(ten)) {
                    throw new RuntimeException("Thể loại phim với tên '" + ten + "' không tồn tại");
                }
                Optional<TheLoaiPhim> theLoaiPhim = theLoaiPhimService.findByTenPhim(ten);
                if (theLoaiPhim.isPresent()) {
                    theLoaiPhimList.add(theLoaiPhim.get());
                }
            }
        }

        Phim phim = Phim.builder()
                .tenPhim(request.getTenPhim())
                .moTa(request.getMoTa())
                .daoDien(request.getDaoDien())
                .dienVien(request.getDienVien())
                .thoiLuong(request.getThoiLuong())
                .ngayKhoiChieu(request.getNgayKhoiChieu())
                .hinhAnh(request.getHinhAnh())
                .trailerURL(request.getTrailerURL())
                .tuoi(request.getTuoi())
                .trangThai(request.getTrangThai())
                .listTheLoai(theLoaiPhimList)
                .build();

        phim.setListTheLoai(theLoaiPhimList);
        
        return phimRepository.save(phim);
    }

    public List<Phim> getAllPhim() {
        return phimRepository.findAll();
    }

    public Phim getPhimById(String maPhim) {
        return phimRepository.findById(maPhim)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phim với mã: " + maPhim));
    }

    public Phim getPhimByTen(String tenPhim) {
        return phimRepository.findByTenPhim(tenPhim)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy phim với tên: " + tenPhim));
    }

    public Phim updatePhim(String maPhim, PhimRequest request) {
        Phim existingPhim = getPhimById(maPhim);
        
        if (!existingPhim.getTenPhim().equals(request.getTenPhim()) && 
            phimRepository.existsByTenPhim(request.getTenPhim())) {
            throw new RuntimeException("Phim với tên '" + request.getTenPhim() + "' đã tồn tại");
        }
        List<TheLoaiPhim> theLoaiPhimList = new ArrayList<>();
        String[] tenTheLoai = request.getTheLoai();
        if (tenTheLoai != null) {
            for (String ten : tenTheLoai) {
                if (!theLoaiPhimService.existsByTenTheLoai(ten)) {
                    throw new RuntimeException("Thể loại phim với tên '" + ten + "' không tồn tại");
                }
                Optional<TheLoaiPhim> theLoaiPhim = theLoaiPhimService.findByTenPhim(ten);
                theLoaiPhim.ifPresent(theLoaiPhimList::add);
            }
        }

        existingPhim.setTenPhim(request.getTenPhim());
        existingPhim.setMoTa(request.getMoTa());
        existingPhim.setDaoDien(request.getDaoDien());
        existingPhim.setDienVien(request.getDienVien());
        existingPhim.setThoiLuong(request.getThoiLuong());
        existingPhim.setNgayKhoiChieu(request.getNgayKhoiChieu());
        existingPhim.setHinhAnh(request.getHinhAnh());
        existingPhim.setTrailerURL(request.getTrailerURL());
        existingPhim.setTuoi(request.getTuoi());
        existingPhim.setTrangThai(request.getTrangThai());
        existingPhim.setListTheLoai(theLoaiPhimList);

        return phimRepository.save(existingPhim);
    }

    public void deletePhim(String maPhim) {
        Phim phim = getPhimById(maPhim);
        phimRepository.delete(phim);
    }

    public Page<Phim> searchPhimByTen(String keyword, Pageable pageable) {
        return phimRepository.findByKeyword(keyword, pageable);
    }

    
    public boolean existsByTenPhim(String tenPhim) {
        return phimRepository.existsByTenPhim(tenPhim);
    }

    public Page<Phim> getPhimPage(Pageable pageable) {
        return phimRepository.findAll(pageable);
    }
}