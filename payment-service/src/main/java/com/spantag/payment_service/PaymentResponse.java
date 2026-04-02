package com.spantag.payment_service;


import java.math.BigDecimal;
import java.time.LocalDateTime;

public class PaymentResponse {
    private String paymentId;
    private Long orderId;
    private String username;
    private BigDecimal amount;
    private String status;      // "SUCCESS" or "FAILED" — matches what SagaOrchestrator checks
    private String message;
    private LocalDateTime createdAt;

    public static PaymentResponse success(Payment p) {
        PaymentResponse r = new PaymentResponse();
        r.paymentId = p.getPaymentId();
        r.orderId   = p.getOrderId();
        r.username  = p.getUsername();
        r.amount    = p.getAmount();
        r.status    = "SUCCESS";
        r.message   = "Payment processed successfully";
        r.createdAt = p.getCreatedAt();
        return r;
    }

    public static PaymentResponse failed(Payment p, String reason) {
        PaymentResponse r = new PaymentResponse();
        r.paymentId = p.getPaymentId();
        r.orderId   = p.getOrderId();
        r.username  = p.getUsername();
        r.amount    = p.getAmount();
        r.status    = "FAILED";
        r.message   = reason;
        r.createdAt = p.getCreatedAt();
        return r;
    }

    public static PaymentResponse from(Payment p) {
        PaymentResponse r = new PaymentResponse();
        r.paymentId = p.getPaymentId();
        r.orderId   = p.getOrderId();
        r.username  = p.getUsername();
        r.amount    = p.getAmount();
        r.status    = p.getStatus().name();
        r.message   = p.getFailureReason() != null ? p.getFailureReason() : "";
        r.createdAt = p.getCreatedAt();
        return r;
    }

    // Getters
    public String getPaymentId()           { return paymentId; }
    public Long getOrderId()               { return orderId; }
    public String getUsername()            { return username; }
    public BigDecimal getAmount()          { return amount; }
    public String getStatus()              { return status; }
    public String getMessage()             { return message; }
    public LocalDateTime getCreatedAt()    { return createdAt; }

	public void setPaymentId(String paymentId) {
		this.paymentId = paymentId;
	}

	public void setOrderId(Long orderId) {
		this.orderId = orderId;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setAmount(BigDecimal amount) {
		this.amount = amount;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}



}
