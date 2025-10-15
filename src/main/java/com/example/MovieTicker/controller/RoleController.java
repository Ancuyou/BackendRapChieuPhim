package com.example.MovieTicker.controller;

import com.example.MovieTicker.request.RoleRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.response.RoleResponse;
import com.example.MovieTicker.service.VaiTroService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final VaiTroService vaiTroService;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<RoleResponse> create(@RequestBody RoleRequest request) {
        return ApiResponse.<RoleResponse>builder()
                .data(vaiTroService.create(request))
                .build();
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<List<RoleResponse>> getAll() {
        return ApiResponse.<List<RoleResponse>>builder()
                .data(vaiTroService.getAll())
                .build();
    }

    @DeleteMapping("/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<Void> delete(@PathVariable int roleId) {
        vaiTroService.delete(roleId);
        return ApiResponse.<Void>builder().build();
    }
}
