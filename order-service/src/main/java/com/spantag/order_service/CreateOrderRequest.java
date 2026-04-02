package com.spantag.order_service;

import java.math.BigDecimal;

public class CreateOrderRequest {
    private String productName;
    private Integer quantity;
    private BigDecimal amount;

    public CreateOrderRequest() {}

    public String getProductName()             { return productName; }
    public void setProductName(String v)       { this.productName = v; }

    public Integer getQuantity()               { return quantity; }
    public void setQuantity(Integer v)         { this.quantity = v; }

    public BigDecimal getAmount()              { return amount; }
    public void setAmount(BigDecimal v)        { this.amount = v; }
}