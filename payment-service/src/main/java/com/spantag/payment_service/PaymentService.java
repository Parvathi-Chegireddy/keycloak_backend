package com.spantag.payment_service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
public class PaymentService {

    private final PaymentRepository paymentRepository;

    public PaymentService(PaymentRepository paymentRepository) {
        this.paymentRepository = paymentRepository;
    }

    /**
     * Called by the saga orchestrator (order-service) — step 2 of the saga.
     *
     * Simulates payment processing:
     *   - amount <= 0    → fails (invalid)
     *   - amount > 10000 → fails (insufficient funds — demonstrates compensation)
     *   - otherwise      → succeeds
     *
     * In production: replace simulateGateway() with Stripe / Razorpay / PayU.
     */
    @Transactional
    public PaymentResponse processPayment(PaymentRequest req) {

        System.out.printf("[PAYMENT] Processing — orderId=%d username=%s amount=%s%n",
                req.getOrderId(), req.getUsername(), req.getAmount());

        if (req.getOrderId() == null || req.getUsername() == null || req.getAmount() == null) {
            PaymentResponse err = new PaymentResponse();
            err.setStatus("FAILED");
            err.setMessage("Invalid payment request — missing required fields");
            return err;
        }

        // Idempotency check — if this order was already processed, return existing result
        var existing = paymentRepository.findByOrderId(req.getOrderId());
        if (existing.isPresent()) {
            Payment p = existing.get();
            System.out.printf("[PAYMENT] Idempotent hit — returning existing payment %s%n",
                    p.getPaymentId());
            return p.getStatus() == PaymentStatus.SUCCESS
                    ? PaymentResponse.success(p)
                    : PaymentResponse.failed(p, p.getFailureReason());
        }

        // Create a payment record as PENDING
        Payment payment = buildPayment(req);
        payment.setStatus(PaymentStatus.PENDING);
        paymentRepository.save(payment);

        // ── Simulate gateway decision ──────────────────────────────────
        boolean paymentSuccess = simulateGateway(req.getAmount());

        if (paymentSuccess) {
            payment.setStatus(PaymentStatus.SUCCESS);
            paymentRepository.save(payment);
            System.out.printf("[PAYMENT] SUCCESS — paymentId=%s%n", payment.getPaymentId());
            return PaymentResponse.success(payment);

        } else {
            String reason = req.getAmount().compareTo(new BigDecimal("10000")) > 0
                    ? "Insufficient funds — amount exceeds ₹10,000 limit"
                    : "Payment declined by gateway";

            // Delete the pending record — failed payments must not be persisted
            System.out.printf("[PAYMENT] FAILED — %s. Deleting pending record.%n", reason);
            paymentRepository.delete(payment);

            PaymentResponse failed = new PaymentResponse();
            failed.setStatus("FAILED");
            failed.setMessage(reason);
            return failed;
        }
    }

    /**
     * Called by saga compensation step — deletes the payment record for an order.
     */
    @Transactional
    public void cancelPayment(Long orderId) {
        paymentRepository.findByOrderId(orderId).ifPresent(payment -> {
            System.out.printf("[PAYMENT] CANCEL — deleting payment for orderId=%d paymentId=%s%n",
                    orderId, payment.getPaymentId());
            paymentRepository.delete(payment);
        });
    }

    /**
     * GET /api/payment/my — returns successful payments for a user.
     */
    public List<PaymentResponse> getMyPayments(String username) {
        return paymentRepository.findByUsername(username)
                .stream().map(PaymentResponse::from).toList();
    }

    /**
     * GET /api/payment/admin/all — returns all payments (admin only).
     */
    public List<PaymentResponse> getAllPayments() {
        return paymentRepository.findAll()
                .stream().map(PaymentResponse::from).toList();
    }

    /* ── helpers ─────────────────────────────────────────────────── */

    private Payment buildPayment(PaymentRequest req) {
        Payment p = new Payment();
        p.setOrderId(req.getOrderId());
        p.setUsername(req.getUsername() != null ? req.getUsername() : "unknown");
        p.setAmount(req.getAmount() != null ? req.getAmount() : BigDecimal.ZERO);
        return p;
    }

    /**
     * Simulates a payment gateway decision.
     * Amounts above 10,000 always fail — demonstrates the saga compensation.
     */
    private boolean simulateGateway(BigDecimal amount) {
        return amount.compareTo(new BigDecimal("10000")) <= 0;
    }
}
