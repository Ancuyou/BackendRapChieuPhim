package com.example.MovieTicker.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "ChiTietDichVuVe")
public class ChiTietDichVuVe {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long maCtdv;

    @Column(nullable = false)
    private Integer soLuong;

    @Column(nullable = false)
    private Double thanhTien;

    @ManyToOne
    @JoinColumn(name = "maVe", nullable = false)
    private Ve ve;

    @ManyToOne
    @JoinColumn(name = "maDv", nullable = false)
    private DichVuDiKem dichVuDiKem;
}
