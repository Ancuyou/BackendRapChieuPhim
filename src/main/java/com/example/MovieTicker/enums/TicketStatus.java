package com.example.MovieTicker.enums;

public enum TicketStatus {
    PROCESSING("PROCESSING", "Đang xử lý"),
    PAID("PAID", "Đã thanh toán"), 
    EXPIRED("EXPIRED", "Đã hết hạn"),
    CANCELLED("CANCELLED", "Đã hủy");

    private final String code;
    private final String description;

    TicketStatus(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}