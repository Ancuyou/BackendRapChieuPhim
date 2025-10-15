package com.example.MovieTicker.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Ghe {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maGhe;

    @Column(columnDefinition = "NVARCHAR(500)", nullable = false)
    private String tenGhe;

    @ManyToOne
    @JoinColumn(name = "MaPhongChieu")
    @JsonIgnore
    private PhongChieu phongChieu;

    @ManyToOne
    @JoinColumn(name = "MaLoaiGhe")
    @JsonIgnoreProperties("listGhe")
    private LoaiGhe loaiGhe;
}
