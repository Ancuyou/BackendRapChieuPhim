package com.example.MovieTicker.entity;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.*;


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DanhGiaPhim {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Min(0)
    @Max(5)
    @Column(nullable = false)
    private Double rating;

    @Column(nullable = false)
    private String comment;

    @ManyToOne
    @JoinColumn(name = "maUser", nullable = false)
    @JsonIgnore
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "maPhim")
    @JsonIgnore
    private Phim phim;

    private LocalDate createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDate.now();
    }
}
