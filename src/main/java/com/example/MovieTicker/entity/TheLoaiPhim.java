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
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
public class TheLoaiPhim {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maTheLoai;

    @Column(length = 255, unique = true, nullable = true)
    private String tenTheLoai;

    @ManyToMany(mappedBy = "listTheLoai", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<Phim> listPhim = new ArrayList<>();

    @PreRemove
    public void preRemove(){
        for (Phim phim : listPhim) {
            phim.getListTheLoai().remove(this);
        }
    }
}
