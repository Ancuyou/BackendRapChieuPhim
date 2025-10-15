package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.DichVuDiKem;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.DichVuDiKemService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;



@RestController
@RequestMapping("/api/dichvudikem")
public class DichVuDiKemController {

    @Autowired
    private DichVuDiKemService service;

    @GetMapping("/pageable")
    public ApiResponse<Map<String, Object>> getDichVuDiKemPageable(@RequestParam(defaultValue = "1") int page,
                            @RequestParam(defaultValue = "5") int size) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<DichVuDiKem> dvdkPage = service.getDichVuDiKemPageable(pageable);
        Map<String, Object> response = Map.of(
            "totalPages", dvdkPage.getTotalPages(),
            "currentItems", dvdkPage.getContent(),
            "currentPage", dvdkPage.getNumber() + 1
        );
        return ApiResponse.<Map<String, Object>>builder()
            .code(200)
            .message("Lấy danh sách dịch vụ đi kèm phân trang thành công")
            .data(response)
            .build();
    }

    @GetMapping
    public ApiResponse<List<DichVuDiKem>> getAll() {
        List<DichVuDiKem> list = service.getAll();
        return ApiResponse.<List<DichVuDiKem>>builder()
                .code(200)
                .message("Lấy danh sách dịch vụ đi kèm thành công")
                .data(list)
                .build();
    }

    @GetMapping("/{id}")
    public ApiResponse<DichVuDiKem> getById(@PathVariable Long id)
    {
        Optional<DichVuDiKem> optional = service.getById(id);
        if (optional.isPresent()) {
            return ApiResponse.<DichVuDiKem>builder()
                    .code(200)
                    .message("Lấy dịch vụ đi kèm thành công")
                    .data(optional.get())
                    .build();
        } else {
            return ApiResponse.<DichVuDiKem>builder()
                    .code(404)
                    .message("Dịch vụ đi kèm không tồn tại")
                    .build();
        }
    }

    @PostMapping
    public ApiResponse<DichVuDiKem> create(@RequestBody DichVuDiKem dichVuDiKem) {
        DichVuDiKem created = service.create(dichVuDiKem);
        return ApiResponse.<DichVuDiKem>builder()
                .code(201)
                .message("Tạo dịch vụ đi kèm thành công")
                .data(created)
                .build();
    }

    @PutMapping("/{id}")
    public ApiResponse<DichVuDiKem> update(@PathVariable Long id,
            @RequestBody DichVuDiKem dichVuDiKem) {
        DichVuDiKem updated = service.update(id, dichVuDiKem);
        return ApiResponse.<DichVuDiKem>builder()
                .code(200)
                .message("Cập nhật dịch vụ đi kèm thành công")
                .data(updated)
                .build();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ApiResponse.<Void>builder()
                .code(200)
                .message("Xóa dịch vụ đi kèm thành công")
                .build();
    }

    @GetMapping("/search")
    public ApiResponse<?> search(@RequestParam("Ten") String tenDv, @RequestParam("Danhmuc") String danhMuc, @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "5") int size) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<DichVuDiKem> dvdkPage = null;
        if (Objects.equals(danhMuc, "all"))
            dvdkPage = service.findDichVuDiKemByTenDvContainingIgnoreCase(tenDv, pageable);
        else dvdkPage = service.searchDichVuDiKem(tenDv, danhMuc, pageable);
        Map<String, Object> response = Map.of(
                "totalPages", dvdkPage.getTotalPages(),
                "currentItems", dvdkPage.getContent(),
                "currentPage", dvdkPage.getNumber() + 1
        );
        return ApiResponse.<Map<String, Object>>builder()
                .code(200)
                .message("Lấy danh sách dịch vụ đi kèm phân trang thành công")
                .data(response)
                .build();
    }

    @GetMapping("/categories")
    public ApiResponse<?> getCategoryDichVu() {
        List<String> categories = service.getAllCategories();
        return ApiResponse.<List<String>>builder()
                .code(200)
                .message("Lấy danh sách danh mục dịch vụ đi kèm thành công")
                .data(categories)
                .build();
    }

    @GetMapping("/category/{tendanhmuc}")
    public ApiResponse<?> getDichVuByCategory(@PathVariable String tendanhmuc) {
        List<DichVuDiKem> list = service.getDichVuByCategory(tendanhmuc);
        return ApiResponse.<List<DichVuDiKem>>builder()
                .code(200)
                .message("Lấy danh sách dịch vụ đi kèm theo danh mục thành công")
                .data(list)
                .build();
    }
    

}