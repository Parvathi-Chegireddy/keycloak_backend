package com.spantag.order_service;

import java.math.BigDecimal;

/**
 * Sent from OrderService → PaymentService during saga step 2.
 */
public class PaymentRequest {
    private Long orderId;
    private String username;
    private BigDecimal amount;

    public PaymentRequest() {}

    public PaymentRequest(Long orderId, String username, BigDecimal amount) {
        this.orderId  = orderId;
        this.username = username;
        this.amount   = amount;
    }

    public Long getOrderId()               { return orderId; }
    public void setOrderId(Long v)         { this.orderId = v; }

    public String getUsername()            { return username; }
    public void setUsername(String v)      { this.username = v; }

    public BigDecimal getAmount()          { return amount; }
    public void setAmount(BigDecimal v)    { this.amount = v; }
}