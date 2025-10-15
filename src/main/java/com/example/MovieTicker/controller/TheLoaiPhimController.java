package com.example.MovieTicker.controller;

import com.example.MovieTicker.entity.Phim;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import com.example.MovieTicker.entity.TheLoaiPhim;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.service.TheLoaiPhimService;

import jakarta.annotation.PostConstruct;

import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/theloai")
public class TheLoaiPhimController {

    @Autowired
    private TheLoaiPhimService theLoaiPhimService;

//    @PostConstruct
//    public void init() {
//        String[] defaultGenres = {"Hành động", "Tình cảm", "Kinh dị", "Hài", "Hoạt hình","Khoa học viễn tưởng","Phiêu lưu","Tâm lý","Chiến tranh","Thể thao","Âm nhạc","Tài liệu"};
//        for (String ten : defaultGenres) {
//            if (!theLoaiPhimService.existsByTenTheLoai(ten)) {
//                TheLoaiPhim tlp = TheLoaiPhim.builder().tenTheLoai(ten).build();
//                theLoaiPhimService.createTheLoaiPhim(tlp);
//            }
//        }
//    }

    @GetMapping("/pageable")
    public ApiResponse<?> getAllTheLoaiPhimPageable(@RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "5") int size) {
        if (page < 1) page = 1;
        if (size < 1) size = 5;
        Pageable pageable = PageRequest.of(page - 1, size);
        Page<TheLoaiPhim> theLoaiPhimPage = theLoaiPhimService.getAllTheLoaiPhim(pageable);
        Map<String, Object> response = Map.of(
                "totalPages", theLoaiPhimPage.getTotalPages(),
                "currentGens", theLoaiPhimPage.getContent(),
                "currentPage", theLoaiPhimPage.getNumber() + 1
        );
        return ApiResponse.<Object>builder()
                .code(200)
                .message("Lấy danh sách thể loại phim thành công")
                .data(response)
                .build();
    }

    @GetMapping
    public ApiResponse<?> getAllTheLoaiPhim() {
        List<TheLoaiPhim> theLoaiPhim = theLoaiPhimService.getAllTheLoaiPhim();
        return ApiResponse.<Object>builder()
                .code(200)
                .message("Lấy danh sách thể loại phim thành công")
                .data(theLoaiPhim)
                .build();
    }


    @GetMapping("/{id}")
    public ApiResponse<?> getTheLoaiPhimById(@PathVariable String id) {
        var theLoaiPhim = theLoaiPhimService.getTheLoaiPhimById(id);
        if (theLoaiPhim != null) {
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Lấy thể loại phim thành công")
                    .data(theLoaiPhim)
                    .build();
        } else {
            return ApiResponse.<Object>builder()
                    .code(404)
                    .message("Không tìm thấy thể loại phim với id: " + id)
                    .build();
        }
    }

    @PostMapping
    public ApiResponse<?> createTheLoaiPhim(@RequestBody TheLoaiPhim theLoaiPhim) {
        if (theLoaiPhimService.existsByTenTheLoai(theLoaiPhim.getTenTheLoai())) {
            return ApiResponse.<Object>builder()
                    .code(400)
                    .message("Thể loại phim với tên '" + theLoaiPhim.getTenTheLoai() + "' đã tồn tại")
                    .build();
        }
        var createdTheLoaiPhim = theLoaiPhimService.createTheLoaiPhim(theLoaiPhim);
        return ApiResponse.<Object>builder()
                .code(201)
                .message("Tạo thể loại phim thành công")
                .data(createdTheLoaiPhim)
                .build();
    }

    @PutMapping("/{id}")
    public ApiResponse<?> updateTheLoaiPhim(@PathVariable String id,@RequestBody TheLoaiPhim theLoaiPhim) {
        var updatedTheLoaiPhim = theLoaiPhimService.updateTheLoaiPhim(id, theLoaiPhim);
        if (updatedTheLoaiPhim != null) {
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Cập nhật thể loại phim thành công")
                    .data(updatedTheLoaiPhim)
                    .build();
        } else {
            return ApiResponse.<Object>builder()
                    .code(404)
                    .message("Không tìm thấy thể loại phim với id: " + id)
                    .build();
        }
    }

    @DeleteMapping("/{id}")
    public ApiResponse<?> deleteTheLoaiPhim(@PathVariable String id) {
        boolean deleted = theLoaiPhimService.deleteTheLoaiPhim(id);
        if (deleted) {
            return ApiResponse.<Object>builder()
                    .code(200)
                    .message("Xóa thể loại phim thành công")
                    .build();
        } else {
            return ApiResponse.<Object>builder()
                    .code(404)
                    .message("Không tìm thấy thể loại phim với id: " + id)
                    .build();
        }
    }

}
