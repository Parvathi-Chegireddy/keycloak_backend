package com.spantag.payment_service;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "payments")
public class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String paymentId;

    @Column(nullable = false)
    private Long orderId;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentStatus status;

    private String failureReason;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (paymentId == null) paymentId = "PAY-" + UUID.randomUUID().toString().toUpperCase();
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

    public String getPaymentId()               { return paymentId; }
    public void setPaymentId(String v)         { this.paymentId = v; }

    public Long getOrderId()                   { return orderId; }
    public void setOrderId(Long v)             { this.orderId = v; }

    public String getUsername()                { return username; }
    public void setUsername(String v)          { this.username = v; }

    public BigDecimal getAmount()              { return amount; }
    public void setAmount(BigDecimal v)        { this.amount = v; }

    public PaymentStatus getStatus()           { return status; }
    public void setStatus(PaymentStatus v)     { this.status = v; }

    public String getFailureReason()               { return failureReason; }
    public void setFailureReason(String v)         { this.failureReason = v; }

    public LocalDateTime getCreatedAt()        { return createdAt; }
    public LocalDateTime getUpdatedAt()        { return updatedAt; }
}
