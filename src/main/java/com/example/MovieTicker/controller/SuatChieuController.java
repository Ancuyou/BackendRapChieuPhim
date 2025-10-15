package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.SuatChieu;
import com.example.MovieTicker.request.SuatChieuRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.SuatChieuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/suatchieu")
public class SuatChieuController {
    @Autowired
    private SuatChieuService suatChieuService;

    @PostMapping
    public ApiResponse<SuatChieu> create(@RequestBody SuatChieuRequest request) {
        SuatChieu sc = suatChieuService.createSuatChieu(request);
        return ApiResponse.<SuatChieu>builder()
                .code(HttpStatus.CREATED.value())
                .message("Tạo suất chiếu thành công")
                .data(sc)
                .build();
    }

    @GetMapping
    public ApiResponse<List<SuatChieu>> getAll() {
        List<SuatChieu> list = suatChieuService.getAllSuatChieu();
        return ApiResponse.<List<SuatChieu>>builder()
                .code(HttpStatus.OK.value())
                .message("Lấy danh sách suất chiếu thành công")
                .data(list)
                .build();
    }
    
    @GetMapping("/pageable")
    public ApiResponse<Map<String, Object>> getSuatChieuPageable(@RequestParam(defaultValue = "1") int page,
                            @RequestParam(defaultValue = "10") int size) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<SuatChieu> suatChieuPage = suatChieuService.getSuatChieuPage(pageable);
        Map<String, Object> response = Map.of(
            "totalPages", suatChieuPage.getTotalPages(),
            "currentItems", suatChieuPage.getContent(),
            "currentPage", suatChieuPage.getNumber() + 1
        );
        return ApiResponse.<Map<String, Object>>builder()
            .code(HttpStatus.OK.value())
            .message("Lấy danh sách suất chiếu phân trang thành công")
            .data(response)
            .build();
    }

    @GetMapping("/{id}")
    public ApiResponse<SuatChieu> getById(@PathVariable String id) {
        SuatChieu sc = suatChieuService.getSuatChieuById(id);
        return ApiResponse.<SuatChieu>builder()
                .code(HttpStatus.OK.value())
                .message("Lấy suất chiếu thành công")
                .data(sc)
                .build();
    }

    @PutMapping("/{id}")
    public ApiResponse<SuatChieu> update(@PathVariable String id, @RequestBody SuatChieuRequest request) {
        SuatChieu sc = suatChieuService.updateSuatChieu(id, request);
        return ApiResponse.<SuatChieu>builder()
                .code(HttpStatus.OK.value())
                .message("Cập nhật suất chiếu thành công")
                .data(sc)
                .build();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<String> delete(@PathVariable String id) {
        suatChieuService.deleteSuatChieu(id);
        return ApiResponse.<String>builder()
                .code(HttpStatus.OK.value())
                .message("Xóa suất chiếu thành công")
                .data(id)
                .build();
    }
}
