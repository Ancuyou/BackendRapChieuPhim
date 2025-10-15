package com.example.MovieTicker.request;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateMomoRefundRequest {
    private String partnerCode;
    private String orderId;
    private String requestId;
    private long amount;
    private String transId;
    private  String lang;
    private String description;
    private String signature;
}
