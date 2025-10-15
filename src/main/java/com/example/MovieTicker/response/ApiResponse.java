package com.example.MovieTicker.response;

import lombok.Getter;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder()
public class ApiResponse<T>{
    @Builder.Default
    private int code = 200;
    private String message;
    private T data;
}
