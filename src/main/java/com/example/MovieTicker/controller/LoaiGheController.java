package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.LoaiGhe;
import com.example.MovieTicker.entity.PhongChieu;
import com.example.MovieTicker.request.LoaiGheRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.LoaiGheService;

import com.example.MovieTicker.service.PhongChieuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequestMapping("/api/loaighe")
public class LoaiGheController {
   @Autowired
   LoaiGheService loaiGheService;

   @Autowired
   PhongChieuService phongChieuService;

   @GetMapping
   public ApiResponse<?> getAllLoaiGhe(@RequestParam("phong") String phong) {
       PhongChieu phongchieu = phongChieuService.getPhongChieuById(phong);
       if (phongchieu == null) {
           List<LoaiGhe> list = loaiGheService.getAllLoaiGhe();
           return ApiResponse.<List<LoaiGhe>>builder()
                   .code(200)
                   .message("Lấy danh sách loại ghế thành công")
                   .data(list)
                   .build();
       }
       List<LoaiGhe> list = loaiGheService.getAllLoaiGheByPhongChieu(phongchieu);
       return ApiResponse.<List<LoaiGhe>>builder()
               .code(200)
               .message("Lấy danh sách loại ghế thành công")
               .data(list)
               .build();
   }

   
   
   @GetMapping("/{id}")
   public ApiResponse<?> getLoaiGheById(@PathVariable String id) {
       LoaiGhe loaiGhe = loaiGheService.getLoaiGheById(id);
       if (loaiGhe != null) {
           return ApiResponse.<LoaiGhe>builder()
                   .code(HttpStatus.OK.value())
                   .message("Lấy thông tin loại ghế thành công")
                   .data(loaiGhe)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy loại ghế với mã: " + id)
                   .build();
       }
   }
   
   @PostMapping
   public ApiResponse<?> createLoaiGhe(@RequestBody LoaiGheRequest request) {
       LoaiGhe loaiGhe = loaiGheService.createLoaiGhe(request);
       return ApiResponse.<LoaiGhe>builder()
               .code(HttpStatus.CREATED.value())
               .message("Tạo loại ghế thành công")
               .data(loaiGhe)
               .build();
   }
   
   @PutMapping("/{id}")
   public ApiResponse<?> updateLoaiGhe(@PathVariable String id, @RequestBody LoaiGheRequest request) {
       LoaiGhe updatedLoaiGhe = loaiGheService.updateLoaiGhe(id, request);
       if (updatedLoaiGhe != null) {
           return ApiResponse.<LoaiGhe>builder()
                   .code(HttpStatus.OK.value())
                   .message("Cập nhật loại ghế thành công")
                   .data(updatedLoaiGhe)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy loại ghế với mã: " + id)
                   .build();
       }
   }
   
   @DeleteMapping("/{id}")
   public ApiResponse<?> deleteLoaiGhe(@PathVariable String id) {
       boolean result = loaiGheService.deleteLoaiGhe(id);
       if (result) {
           return ApiResponse.<String>builder()
                   .code(HttpStatus.OK.value())
                   .message("Xóa loại ghế thành công")
                   .data(id)
                   .build();
       } else {
           return ApiResponse.builder()
                   .code(HttpStatus.NOT_FOUND.value())
                   .message("Không tìm thấy loại ghế với mã: " + id)
                   .build();
       }
   }
}
