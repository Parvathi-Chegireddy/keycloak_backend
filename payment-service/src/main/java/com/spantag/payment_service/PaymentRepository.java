package com.spantag.payment_service;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
    Optional<Payment> findByOrderId(Long orderId);
    Optional<Payment> findByPaymentId(String paymentId);
    List<Payment> findByUsername(String username);
    List<Payment> findByStatus(PaymentStatus status);
}