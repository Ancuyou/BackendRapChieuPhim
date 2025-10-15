package com.example.MovieTicker.entity;
import java.util.List;

import jakarta.persistence.*;
import lombok.*;
import java.util.Set;
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "VaiTro")
public class VaiTro {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int vaiTroId;
    private String tenVaiTro;
    @OneToMany(mappedBy = "vaiTro", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<TaiKhoan> taiKhoans;
    @ManyToMany
    private Set<Permission> permissions;
}
