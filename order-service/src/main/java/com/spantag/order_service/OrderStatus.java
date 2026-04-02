package com.spantag.order_service;

public enum OrderStatus {
    PENDING,       // order created, saga not started yet
    PROCESSING,    // saga in progress — payment being attempted
    CONFIRMED,     // payment succeeded — order complete
    CANCELLED      // payment failed — saga compensated
}