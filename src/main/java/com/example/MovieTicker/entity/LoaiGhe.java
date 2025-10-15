package com.example.MovieTicker.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class LoaiGhe {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String maLoaiGhe;

    @Column(length = 255,  nullable = false,unique = true)
    private String tenLoaiGhe;

    private float phuThu;

    @OneToMany(mappedBy = "loaiGhe", cascade = {CascadeType.MERGE, CascadeType.PERSIST})
    List<Ghe> listGhe = new ArrayList<>();

    @PreRemove
    public void preRemove(){
        for (Ghe ghe : listGhe){
            ghe.setLoaiGhe(null);
        }
    }
}
