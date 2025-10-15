package com.example.MovieTicker.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;
import java.util.Date;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
public class InvalidatedToken {
    @Id
    String id;
    Date expiryDate;
}