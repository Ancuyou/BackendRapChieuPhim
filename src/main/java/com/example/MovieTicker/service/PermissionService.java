package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.Permission;
import com.example.MovieTicker.exception.AppException;
import com.example.MovieTicker.exception.ErrorCode;
import com.example.MovieTicker.mapper.PermissionMapper;
import com.example.MovieTicker.repository.PermissionRepository;
import com.example.MovieTicker.request.PermissionRequest;
import com.example.MovieTicker.response.PermissionResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final PermissionMapper permissionMapper;

    public PermissionResponse create(PermissionRequest request){
        if(permissionRepository.existsById(request.getName())){
            throw new AppException(ErrorCode.PERMISSION_ALREADY_EXISTS);
        }
        Permission permission = permissionMapper.toPermission(request);
        permission = permissionRepository.save(permission);
        return permissionMapper.toPermissionResponse(permission);
    }

    public List<PermissionResponse> getAll(){
        var permissions = permissionRepository.findAll();
        return permissions.stream().map(permissionMapper::toPermissionResponse).collect(Collectors.toList());
    }

    public void delete(String name){
        permissionRepository.deleteById(name);
    }
}
