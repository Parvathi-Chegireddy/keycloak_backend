package com.spantag.order_service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

@Service
public class SagaOrchestrator {

    private final OrderRepository orderRepository;
    private final WebClient paymentClient;

    public SagaOrchestrator(
            OrderRepository orderRepository,
            @Value("${payment.service.url}") String paymentServiceUrl) {
        this.orderRepository = orderRepository;
        this.paymentClient   = WebClient.builder()
                .baseUrl(paymentServiceUrl)
                .build();
    }

    
    public Order executeSaga(Order order) {

        log("STEP 1 — Order created as PENDING", order);
        order.setStatus(OrderStatus.PROCESSING);
        orderRepository.save(order);

        log("STEP 2 — Calling payment service", order);
        PaymentResponse paymentResponse = processPayment(order);

        if (paymentResponse != null && paymentResponse.isSuccess()) {

            log("STEP 3 — CONFIRMED, paymentId=" + paymentResponse.getPaymentId(), order);
            order.setStatus(OrderStatus.CONFIRMED);
            order.setPaymentId(paymentResponse.getPaymentId());
            orderRepository.save(order);

        } else {

            String reason = (paymentResponse != null)
                    ? paymentResponse.getMessage()
                    : "Payment service unreachable";
            log("COMPENSATION — reason: " + reason, order);
            compensate(order, reason);
        }

        return order;
    }


    private PaymentResponse processPayment(Order order) {
        try {
            PaymentRequest req = new PaymentRequest(
                    order.getId(),
                    order.getUsername(),
                    order.getAmount()
            );

            return paymentClient.post()
                    .uri("/api/payment/process")
                    .bodyValue(req)
                    .retrieve()
                    .bodyToMono(PaymentResponse.class)
                    .block();

        } catch (WebClientResponseException e) {
            System.err.printf("[SAGA] Payment service returned %s: %s%n",
                    e.getStatusCode(), e.getMessage());
            PaymentResponse failed = new PaymentResponse();
            failed.setStatus("FAILED");
            failed.setMessage("Payment service error: " + e.getStatusCode());
            return failed;

        } catch (Exception e) {
            System.err.printf("[SAGA] Payment service unreachable: %s%n", e.getMessage());
            return null;
        }
    }


    private void compensate(Order order, String reason) {
        try {
            paymentClient.post()
                    .uri("/api/payment/cancel/" + order.getId())
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log("COMPENSATION — payment cancel request sent", order);
        } catch (Exception e) {
            System.err.printf("[SAGA] Could not reach payment service for cancel: %s%n",
                    e.getMessage());
        }

    
        log("COMPENSATION — deleting order from DB. Reason: " + reason, order);
        orderRepository.delete(order);

        order.setStatus(OrderStatus.CANCELLED);
        order.setCancellationReason(reason);
    }

    private void log(String step, Order order) {
        System.out.printf("[SAGA] %s | orderId=%d username=%s amount=%s%n",
                step, order.getId(), order.getUsername(), order.getAmount());
    }
}
