package com.example.MovieTicker.response;

import lombok.Data;
import java.util.Set;

@Data
public class RoleResponse {
    private int vaiTroId;
    private String name;
    private String description;
    private Set<PermissionResponse> permissions;
}
