package com.example.MovieTicker.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.MovieTicker.request.TicketBookingRequest;
import com.example.MovieTicker.response.ApiResponse;
import com.example.MovieTicker.response.HoaDonResponse;
import com.example.MovieTicker.service.VeService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api/ve")
public class VeController {
    @Autowired
    private VeService veService;

    @PostMapping
    public ApiResponse<HoaDonResponse> booking(@RequestBody TicketBookingRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) 
        throws IOException
    {
        HoaDonResponse result = veService.createTickets(request, httpRequest, httpResponse);

        return ApiResponse.<HoaDonResponse>builder()
                .code(200)
                .message("Đặt vé thành công - Đang xử lý")
                .data(result)
                .build();
        
    }
    
}
