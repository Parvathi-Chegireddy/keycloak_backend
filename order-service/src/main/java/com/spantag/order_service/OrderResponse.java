package com.spantag.order_service;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public class OrderResponse {
    private Long orderId;
    private String username;
    private String productName;
    private Integer quantity;
    private BigDecimal amount;
    private String status;
    private String paymentId;
    private String cancellationReason;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String message; // error message field

    public static OrderResponse from(Order o) {
        OrderResponse r = new OrderResponse();
        r.orderId            = o.getId();
        r.username           = o.getUsername();
        r.productName        = o.getProductName();
        r.quantity           = o.getQuantity();
        r.amount             = o.getAmount();
        r.status             = o.getStatus().name();
        r.paymentId          = o.getPaymentId();
        r.cancellationReason = o.getCancellationReason();
        r.createdAt          = o.getCreatedAt();
        r.updatedAt          = o.getUpdatedAt();
        return r;
    }

    public Long getOrderId()                      { return orderId; }
    public void setOrderId(Long v)                { this.orderId = v; }

    public String getUsername()                   { return username; }
    public void setUsername(String v)             { this.username = v; }

    public String getProductName()                { return productName; }
    public void setProductName(String v)          { this.productName = v; }

    public Integer getQuantity()                  { return quantity; }
    public void setQuantity(Integer v)            { this.quantity = v; }

    public BigDecimal getAmount()                 { return amount; }
    public void setAmount(BigDecimal v)           { this.amount = v; }

    public String getStatus()                     { return status; }
    public void setStatus(String v)               { this.status = v; }

    public String getPaymentId()                  { return paymentId; }
    public void setPaymentId(String v)            { this.paymentId = v; }

    public String getCancellationReason()         { return cancellationReason; }
    public void setCancellationReason(String v)   { this.cancellationReason = v; }

    public LocalDateTime getCreatedAt()           { return createdAt; }
    public void setCreatedAt(LocalDateTime v)     { this.createdAt = v; }

    public LocalDateTime getUpdatedAt()           { return updatedAt; }
    public void setUpdatedAt(LocalDateTime v)     { this.updatedAt = v; }

    public String getMessage()                    { return message; }
    public void setMessage(String v)              { this.message = v; }
}
