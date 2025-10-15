package com.example.MovieTicker.controller;

import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
   

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import com.example.MovieTicker.entity.Phim;
import com.example.MovieTicker.request.PhimRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.PhimService;


@RestController
@RequestMapping("/api/phim")
public class PhimController {

    @Autowired
    private PhimService phimService;

    @GetMapping("/pageable")
    public ApiResponse<Map<String, Object>> getPhimPageable(@RequestParam(defaultValue = "1") int page,
                               @RequestParam(defaultValue = "8") int size) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<Phim> phimPage = phimService.getPhimPage(pageable);
        Map<String, Object> response = Map.of(
            "totalPages", phimPage.getTotalPages(),
            "currentMovies", phimPage.getContent(),
            "currentPage", phimPage.getNumber() + 1
        );
        return ApiResponse.<Map<String, Object>>builder()
            .code(HttpStatus.OK.value())
            .message("Lấy danh sách phim phân trang thành công")
            .data(response)
            .build();
    }
    @PostMapping
    public ApiResponse<Phim> createPhim(@RequestBody PhimRequest request) {
        try {
            Phim phim = phimService.createPhim(request);
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.CREATED.value())
                    .message("Tạo phim thành công")
                    .data(phim)
                    .build();
        } catch (RuntimeException e) {
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @GetMapping
    public ApiResponse<List<Phim>> getAllPhim() {
        List<Phim> phimList = phimService.getAllPhim();
        return ApiResponse.<List<Phim>>builder()
                .code(HttpStatus.OK.value())
                .message("Lấy danh sách phim thành công")
                .data(phimList)
                .build();
    }

    @GetMapping("/{maPhim}")
    public ApiResponse<Phim> getPhimById(@PathVariable String maPhim) {
        try {
            Phim phim = phimService.getPhimById(maPhim);
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.OK.value())
                    .message("Lấy thông tin phim thành công")
                    .data(phim)
                    .build();
        } catch (RuntimeException e) {
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.NOT_FOUND.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @PutMapping("/{maPhim}")
    public ApiResponse<Phim> updatePhim(@PathVariable String maPhim, @RequestBody PhimRequest request) {
        try {
            Phim phim = phimService.updatePhim(maPhim, request);
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.OK.value())
                    .message("Cập nhật phim thành công")
                    .data(phim)
                    .build();
        } catch (RuntimeException e) {
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @DeleteMapping("/{maPhim}")
    public ApiResponse<String> deletePhim(@PathVariable String maPhim) {
        try {
            phimService.deletePhim(maPhim);
            return ApiResponse.<String>builder()
                    .code(HttpStatus.OK.value())
                    .message("Xóa phim thành công")
                    .data("Phim với mã " + maPhim + " đã được xóa")
                    .build();
        } catch (RuntimeException e) {
            return ApiResponse.<String>builder()
                    .code(HttpStatus.NOT_FOUND.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @GetMapping("/search")
    public ApiResponse<Map<String, Object>> searchPhim(@RequestParam String keyword, @RequestParam(defaultValue = "1") int page,
                                              @RequestParam(defaultValue = "8") int size) {
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<Phim> phimPage = phimService.searchPhimByTen(keyword, pageable);
        Map<String, Object> response = Map.of(
                "totalPages", phimPage.getTotalPages(),
                "currentMovies", phimPage.getContent(),
                "currentPage", phimPage.getNumber() + 1
        );
        return ApiResponse.<Map<String, Object>>builder()
                .code(HttpStatus.OK.value())
                .message("Tìm kiếm phim thành công")
                .data(response)
                .build();
    }


    
    @GetMapping("/ten/{tenPhim}")
    public ApiResponse<Phim> getPhimByTen(@PathVariable String tenPhim) {
        try {
            Phim phim = phimService.getPhimByTen(tenPhim);
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.OK.value())
                    .message("Lấy phim theo tên thành công")
                    .data(phim)
                    .build();
        } catch (RuntimeException e) {
            return ApiResponse.<Phim>builder()
                    .code(HttpStatus.NOT_FOUND.value())
                    .message(e.getMessage())
                    .build();
        }
    }



    @GetMapping("/exists/{tenPhim}")
    public ApiResponse<Boolean> checkPhimExists(@PathVariable String tenPhim) {
        boolean exists = phimService.existsByTenPhim(tenPhim);
        return ApiResponse.<Boolean>builder()
                .code(HttpStatus.OK.value())
                .message("Kiểm tra phim tồn tại thành công")
                .data(exists)
                .build();
    }
}