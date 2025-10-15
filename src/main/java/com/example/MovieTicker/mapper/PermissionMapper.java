package com.example.MovieTicker.mapper;

import com.example.MovieTicker.entity.Permission;
import com.example.MovieTicker.request.PermissionRequest;
import com.example.MovieTicker.response.PermissionResponse;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface PermissionMapper {
    Permission toPermission(PermissionRequest request);
    PermissionResponse toPermissionResponse(Permission permission);
}