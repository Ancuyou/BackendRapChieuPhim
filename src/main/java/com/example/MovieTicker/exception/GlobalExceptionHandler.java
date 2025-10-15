package com.example.MovieTicker.exception;

import java.sql.SQLIntegrityConstraintViolationException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.example.MovieTicker.response.ApiResponse;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(value = RuntimeException.class)
    ResponseEntity<ApiResponse<String>> handleRuntimeException(RuntimeException ex) {
        ApiResponse<String> apiResponse = new ApiResponse<>();
        apiResponse.setCode(400);
        apiResponse.setMessage(ex.getMessage());
        return ResponseEntity.badRequest().body(apiResponse);
    }
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<?> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 400);
        body.put("message", ex.getRootCause() != null ? ex.getRootCause().getMessage() : ex.getMessage());
        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(SQLIntegrityConstraintViolationException.class)
    public ResponseEntity<?> handleSQLIntegrity(SQLIntegrityConstraintViolationException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 400);
        body.put("message", ex.getMessage());
        return ResponseEntity.badRequest().body(body);
    }
}
