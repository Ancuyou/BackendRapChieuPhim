package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.Phim;
import com.example.MovieTicker.entity.TaiKhoan;
import com.example.MovieTicker.entity.User;
import com.example.MovieTicker.request.PhimRequest;
import com.example.MovieTicker.request.UserRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    UserService userService;

    @GetMapping("")
    public ApiResponse<Map<String,Object>> findAll(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "5") int size
    ) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page, size);
        Page<TaiKhoan> taiKhoanPage = userService.findAll(pageable);
        Map<String,Object> response = Map.of(
                "totalPages",taiKhoanPage.getTotalPages(),
                "currentTaiKhoan",taiKhoanPage.getContent(),
                "currentPage",taiKhoanPage.getNumber() + 1
        );
        return ApiResponse.<Map<String,Object>>builder()
                .code(HttpStatus.OK.value())
                .message(("Lấy danh sách tài khoản thành công"))
                .data(response)
                .build();
    }

    @PostMapping("")
    public ApiResponse<?> create(@RequestBody TaiKhoan request) {
        try {
            TaiKhoan taiKhoan = userService.save(request);
            return ApiResponse.builder()
                    .code(HttpStatus.CREATED.value())
                    .message("Tạo user thành công")
                    .data(taiKhoan)
                    .build();
        } catch (Exception e) {
            return ApiResponse.builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @PutMapping("/{id}")
    public ApiResponse<?> update(@PathVariable String id, @RequestBody TaiKhoan request) {
        try {
            Optional<TaiKhoan> taiKhoan = userService.findById(id);
            request.setTenDangNhap(taiKhoan.get().getTenDangNhap());
            userService.save(request);
            return ApiResponse.builder()
                    .code(HttpStatus.CREATED.value())
                    .message("Cập nhật user thành công")
                    .data(taiKhoan)
                    .build();
        }  catch (Exception e) {
            return ApiResponse.builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .message(e.getMessage())
                    .build();
        }
    }

    @DeleteMapping("/{id}")
    public ApiResponse<?> delete(@PathVariable String id) {
        try {
            Optional<TaiKhoan> taiKhoan = userService.findById(id);
            userService.deleteById(id);
            return ApiResponse.builder()
                    .code(HttpStatus.OK.value())
                    .message("Xóa user thành công")
                    .data(taiKhoan)
                    .build();
        }
        catch (Exception e) {
            return ApiResponse.builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .message(e.getMessage())
                    .build();
        }
    }
}
