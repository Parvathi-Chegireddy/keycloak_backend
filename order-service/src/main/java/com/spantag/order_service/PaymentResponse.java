package com.spantag.order_service;

public class PaymentResponse {
    private String paymentId;
    private String status;   // "SUCCESS" or "FAILED"
    private String message;

    public PaymentResponse() {}

    public String getPaymentId()           { return paymentId; }
    public void setPaymentId(String v)     { this.paymentId = v; }

    public String getStatus()              { return status; }
    public void setStatus(String v)        { this.status = v; }

    public String getMessage()             { return message; }
    public void setMessage(String v)       { this.message = v; }

    public boolean isSuccess() {
        return "SUCCESS".equalsIgnoreCase(status);
    }
}