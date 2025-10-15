package com.example.MovieTicker.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateMomoRequest {
    private String partnerCode;
    private String requestType;
    private String ipnUrl;
    private String orderId;
    private String orderInfo;
    private long amount;
    private String requestId;
    private String redirectUrl;
    private  String lang;
    private String extraData;
    private String signature;
}
