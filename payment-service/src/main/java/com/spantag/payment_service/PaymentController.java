package com.spantag.payment_service;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    private final PaymentService paymentService;

    public PaymentController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    /**
     * POST /api/payment/process
     *
     * Called INTERNALLY by the saga orchestrator in order-service.
     * NOT routed through the gateway — direct service-to-service call.
     * Security: payment service is bound to 127.0.0.1 so only
     * services on the same host can call it.
     */
    @PostMapping("/process")
    public ResponseEntity<PaymentResponse> processPayment(
            @RequestBody PaymentRequest req) {

        if (req.getOrderId() == null || req.getAmount() == null) {
            PaymentResponse err = new PaymentResponse();
            err.setStatus("FAILED");
            err.setMessage("orderId and amount are required");
            return ResponseEntity.badRequest().body(err);
        }

        PaymentResponse response = paymentService.processPayment(req);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/payment/cancel/{orderId}
     *
     * Called INTERNALLY by the saga orchestrator's compensation step.
     * NOT routed through the gateway.
     */
    @PostMapping("/cancel/{orderId}")
    public ResponseEntity<Map<String, String>> cancelPayment(
            @PathVariable Long orderId) {
        paymentService.cancelPayment(orderId);
        return ResponseEntity.ok(Map.of("message", "Payment cancelled for orderId: " + orderId));
    }

    /**
     * GET /api/payment/my
     * Returns payments for the authenticated user.
     * Routed through gateway with JwtAuthFilter.
     */
    @GetMapping("/my")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentResponse>> getMyPayments(Principal principal) {
        return ResponseEntity.ok(paymentService.getMyPayments(principal.getName()));
    }

    /**
     * GET /api/payment/admin/all
     * Admin only — all payments.
     */
    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PaymentResponse>> getAllPayments() {
        return ResponseEntity.ok(paymentService.getAllPayments());
    }
}