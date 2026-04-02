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

    
    @PostMapping("/cancel/{orderId}")
    public ResponseEntity<Map<String, String>> cancelPayment(
            @PathVariable Long orderId) {
        paymentService.cancelPayment(orderId);
        return ResponseEntity.ok(Map.of("message", "Payment cancelled for orderId: " + orderId));
    }

    
    @GetMapping("/my")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentResponse>> getMyPayments(Principal principal) {
        return ResponseEntity.ok(paymentService.getMyPayments(principal.getName()));
    }

    
    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PaymentResponse>> getAllPayments() {
        return ResponseEntity.ok(paymentService.getAllPayments());
    }
}
