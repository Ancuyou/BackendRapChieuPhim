package com.example.MovieTicker.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.MovieTicker.request.DanhGiaPhimRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.response.DanhGiaPhimResponse;
import com.example.MovieTicker.service.DanhGiaPhimService;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;



@RestController
@RequestMapping("/api/danhgiaphim")
public class DanhGiaPhimController {

    @Autowired
    private DanhGiaPhimService danhGiaPhimService;

    @GetMapping("/phim/{maPhim}")
    public ApiResponse<?> getDanhSachDanhGiaByPhimId(@PathVariable String maPhim) {
        return ApiResponse.<Object>builder()
                .code(200)
                .message("Lấy danh sách đánh giá phim theo mã phim thành công")
                .data(danhGiaPhimService.getDanhGiaByPhimId(maPhim))
                .build();
    }

    @PostMapping
    public ApiResponse<?> createDanhGiaPhim(@RequestBody DanhGiaPhimRequest request) {
        return ApiResponse.<Object>builder()
                .code(201)
                .message("Tạo đánh giá phim thành công")
                .data(danhGiaPhimService.saveDanhGiaPhim(request))
                .build();
    }
    

    @GetMapping
    public ApiResponse<?> getAllDanhGiaPhim() {
        return ApiResponse.<Object>builder()
                .code(200)
                .message("Lấy tất cả đánh giá phim thành công")
                .data(danhGiaPhimService.getAllDanhGiaPhim())
                .build();
    }

    @GetMapping("/{id}")
    public ApiResponse<?> getDanhGiaPhimById(@PathVariable String id) {
        return ApiResponse.<Object>builder()
                .code(200)
                .message("Lấy đánh giá phim theo ID thành công")
                .data(danhGiaPhimService.getDanhGiaPhimById(id))
                .build();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<?> deleteDanhGiaPhim(@PathVariable String id) {
        try {
            danhGiaPhimService.deleteDanhGiaPhim(id);
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Xóa đánh giá phim thành công")
                    .build();
        } catch (Exception e) {
            return ApiResponse.<Object>builder()
                    .code(400)
                    .message("Lỗi: " + e.getMessage())
                    .build();
        }
    }

    @org.springframework.web.bind.annotation.PutMapping("/{id}")
    public ApiResponse<?> updateDanhGiaPhim(@PathVariable String id, @RequestBody DanhGiaPhimRequest request) {
        try {
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Cập nhật đánh giá phim thành công")
                    .data(danhGiaPhimService.updateDanhGia(id, request))
                    .build();
        } catch (Exception e) {
            return ApiResponse.<Object>builder()
                    .code(400)
                    .message("Lỗi: " + e.getMessage())
                    .build();
        }
    }

    @GetMapping("/paginated")
    public ApiResponse<?> getDanhGiaPhimPaginated(
            @RequestParam(required = false, defaultValue = "") String tenPhim,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "5") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDirection) {
        try {
            if (page < 1) page = 1;
            if (size < 1) size = 10;
            
            Page<DanhGiaPhimResponse> danhGiaPage = danhGiaPhimService.getDanhGiaPhimPaginated(
                    tenPhim, page - 1, size, sortBy, sortDirection);
            
            java.util.Map<String, Object> response = java.util.Map.of(
                "totalPages", danhGiaPage.getTotalPages(),
                "currentReview", danhGiaPage.getContent(),
                "currentPage", danhGiaPage.getNumber() + 1
            );
            
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Lấy danh sách đánh giá phim phân trang thành công")
                    .data(response)
                    .build();
        } catch (Exception e) {
            return ApiResponse.<Object>builder()
                    .code(400)
                    .message("Lỗi: " + e.getMessage())
                    .build();
        }
    }

}
