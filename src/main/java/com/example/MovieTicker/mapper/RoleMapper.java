package com.example.MovieTicker.mapper;

import com.example.MovieTicker.entity.VaiTro;
import com.example.MovieTicker.request.RoleRequest;
import com.example.MovieTicker.response.RoleResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring", uses = {PermissionMapper.class})
public interface RoleMapper {
    @Mapping(target = "permissions", ignore = true)
    @Mapping(target = "tenVaiTro", source = "name")
    VaiTro toVaiTro(RoleRequest request);

    @Mapping(target = "name", source = "tenVaiTro")
    RoleResponse toRoleResponse(VaiTro vaiTro);
}
