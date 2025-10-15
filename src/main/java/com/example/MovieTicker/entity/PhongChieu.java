package com.example.MovieTicker.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PhongChieu {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maPhongChieu;

    @Column(length = 255, unique = true, nullable = false)
    private String tenPhong;

    private int soLuongGhe;

    @OneToMany(mappedBy = "phongChieu", cascade = CascadeType.ALL)
    private List<Ghe> listGhe = new ArrayList<>();

    @OneToMany(mappedBy = "phongChieu", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<SuatChieu> listSuatChieu = new ArrayList<>();
}
