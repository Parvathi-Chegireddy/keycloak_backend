package com.spantag.payment_service;

import java.math.BigDecimal;

public class PaymentRequest {
    private Long orderId;
    private String username;
    private BigDecimal amount;

    public PaymentRequest() {}

    public Long getOrderId()               { return orderId; }
    public void setOrderId(Long v)         { this.orderId = v; }

    public String getUsername()            { return username; }
    public void setUsername(String v)      { this.username = v; }

    public BigDecimal getAmount()          { return amount; }
    public void setAmount(BigDecimal v)    { this.amount = v; }
}