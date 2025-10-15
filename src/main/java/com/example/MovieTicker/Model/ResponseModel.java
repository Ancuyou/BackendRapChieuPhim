package com.example.MovieTicker.Model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResponseModel implements Serializable {
    private String status;
    private String message;
    private Object data;
}