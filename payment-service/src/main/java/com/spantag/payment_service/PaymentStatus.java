package com.spantag.payment_service;

public enum PaymentStatus {
    PENDING,    // payment record created, not yet processed
    SUCCESS,    // payment processed successfully
    FAILED,     // payment processing failed
    CANCELLED   // payment cancelled by saga compensation
}