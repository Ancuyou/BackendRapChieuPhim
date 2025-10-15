package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.VaiTro;
import com.example.MovieTicker.exception.AppException;
import com.example.MovieTicker.exception.ErrorCode;
import com.example.MovieTicker.mapper.RoleMapper;
import com.example.MovieTicker.repository.PermissionRepository;
import com.example.MovieTicker.repository.VaiTroRepository;
import com.example.MovieTicker.request.RoleRequest;
import com.example.MovieTicker.response.RoleResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaiTroService {

    private final VaiTroRepository vaiTroRepository;
    private final PermissionRepository permissionRepository;
    private final RoleMapper roleMapper;

    public RoleResponse create(RoleRequest request) {
        if (vaiTroRepository.findByTenVaiTro(request.getName()).isPresent()) {
            throw new AppException(ErrorCode.ROLE_ALREADY_EXISTS);
        }

        var vaiTro = roleMapper.toVaiTro(request);
        var permissions = permissionRepository.findAllById(request.getPermissions());
        vaiTro.setPermissions(new HashSet<>(permissions));

        vaiTro = vaiTroRepository.save(vaiTro);
        return roleMapper.toRoleResponse(vaiTro);
    }

    public List<RoleResponse> getAll() {
        return vaiTroRepository.findAll()
                .stream()
                .map(roleMapper::toRoleResponse)
                .collect(Collectors.toList());
    }

    public void delete(int roleId) {
        vaiTroRepository.deleteById(roleId);
    }
}