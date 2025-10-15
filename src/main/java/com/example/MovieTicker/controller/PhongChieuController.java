package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.Ghe;
import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.request.PhongChieuRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.GheService;
import com.example.MovieTicker.service.PhongChieuService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequestMapping("/api/phongchieu")
public class PhongChieuController {
   @Autowired
   PhongChieuService phongChieuService;

    @Autowired
    GheService gheService;

    @GetMapping
   public ApiResponse<?> getListPhongChieu() {
         return ApiResponse.<List<PhongChieu>>builder()
           .code(200)
           .message("Lấy danh sách phòng chiếu thành công")
           .data(phongChieuService.getListPhongChieu())
           .build();
   }
   
   @GetMapping("/pageable")
   public ApiResponse<Map<String, Object>> getPhongChieuPageable(@RequestParam(defaultValue = "1") int page,
                           @RequestParam(defaultValue = "10") int size) {
       if (page < 1) page = 1;
       if (size < 1) size = 5;
       Pageable pageable = PageRequest.of(page - 1, size);
       Page<PhongChieu> phongChieuPage = phongChieuService.getPhongChieuPage(pageable);
       Map<String, Object> response = Map.of(
           "totalPages", phongChieuPage.getTotalPages(),
           "currentItems", phongChieuPage.getContent(),
           "currentPage", phongChieuPage.getNumber() + 1
       );
       return ApiResponse.<Map<String, Object>>builder()
           .code(HttpStatus.OK.value())
           .message("Lấy danh sách phòng chiếu phân trang thành công")
           .data(response)
           .build();
   }
   
   @GetMapping("/{id}")
   public ApiResponse<?> getPhongChieuById(@PathVariable String id) {
       PhongChieu phongChieu = phongChieuService.getPhongChieuById(id);
       if (phongChieu != null) {
           return ApiResponse.builder()
                   .code(HttpStatus.OK.value())
                   .message("Lấy thông tin phòng chiếu thành công")
                   .data(phongChieu)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy phòng chiếu với mã: " + id)
                   .build();
       }
   }
   
   @PostMapping
   public ApiResponse<?> createPhongChieu(@RequestBody PhongChieuRequest request) {
       PhongChieu phongChieu = phongChieuService.createPhongChieu(request);
       return ApiResponse.<PhongChieu>builder()
               .code(HttpStatus.CREATED.value())
               .message("Tạo phòng chiếu thành công")
               .data(phongChieu)
               .build();
   }
   
   @PutMapping("/{id}")
   public ApiResponse<?> updatePhongChieu(@PathVariable String id, @RequestBody PhongChieuRequest request) {
       PhongChieu updatedPhongChieu = phongChieuService.updatePhongChieu(id, request);
       if (updatedPhongChieu != null) {
           return ApiResponse.<PhongChieu>builder()
                   .code(HttpStatus.OK.value())
                   .message("Cập nhật phòng chiếu thành công")
                   .data(updatedPhongChieu)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy phòng chiếu với mã: " + id)
                   .build();
       }
   }
   
   @DeleteMapping("/{id}")
   public ApiResponse<?> deletePhongChieu(@PathVariable String id) {
       boolean result = phongChieuService.deletePhongChieu(id);
       if (result) {
           return ApiResponse.<String>builder()
                   .code(HttpStatus.OK.value())
                   .message("Xóa phòng chiếu thành công")
                   .data(id)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy phòng chiếu với mã: " + id)
                   .build();
       }
   }
}
