package com.example.MovieTicker.config;

import com.example.MovieTicker.request.CreateMomoRefundRequest;
import com.example.MovieTicker.request.CreateMomoRequest;
import com.example.MovieTicker.response.CreateMomoResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@FeignClient(name = "momo", url = "${momo.endpoint}")
public interface MomoAPI {

    @PostMapping("/create")
    CreateMomoResponse createMomoQR(@RequestBody CreateMomoRequest request);

    @PostMapping("/refund")
    CreateMomoResponse createMomoRefund(@RequestBody CreateMomoRefundRequest request);

}
