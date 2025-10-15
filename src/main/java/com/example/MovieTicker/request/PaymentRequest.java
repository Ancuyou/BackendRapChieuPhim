package com.example.MovieTicker.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PaymentRequest {
    private long amount;
    private String orderId;
    private String requestId;
    private String transId;
    private String transDate;
    private String transType;

    public PaymentRequest(long amount, String orderId) {
        this.amount = amount;
        this.orderId = orderId;
    }
}
