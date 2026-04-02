package com.spantag.order_service;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "orders")
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Username from JWT — injected by gateway as X-Auth-Username
    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String productName;

    @Column(nullable = false)
    private Integer quantity;

    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OrderStatus status;

    // Filled in once payment service processes the transaction
    private String paymentId;

    // Reason stored when order is cancelled
    private String cancellationReason;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Getters & Setters
    public Long getId()                        { return id; }
    public void setId(Long id)                 { this.id = id; }

    public String getUsername()                { return username; }
    public void setUsername(String v)          { this.username = v; }

    public String getProductName()             { return productName; }
    public void setProductName(String v)       { this.productName = v; }

    public Integer getQuantity()               { return quantity; }
    public void setQuantity(Integer v)         { this.quantity = v; }

    public BigDecimal getAmount()              { return amount; }
    public void setAmount(BigDecimal v)        { this.amount = v; }

    public OrderStatus getStatus()             { return status; }
    public void setStatus(OrderStatus v)       { this.status = v; }

    public String getPaymentId()               { return paymentId; }
    public void setPaymentId(String v)         { this.paymentId = v; }

    public String getCancellationReason()          { return cancellationReason; }
    public void setCancellationReason(String v)    { this.cancellationReason = v; }

    public LocalDateTime getCreatedAt()        { return createdAt; }
    public LocalDateTime getUpdatedAt()        { return updatedAt; }
}