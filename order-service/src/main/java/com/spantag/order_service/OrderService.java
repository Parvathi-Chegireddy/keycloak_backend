package com.spantag.order_service;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class OrderService {

    private final OrderRepository orderRepository;
    private final SagaOrchestrator sagaOrchestrator;

    public OrderService(OrderRepository orderRepository,
                        SagaOrchestrator sagaOrchestrator) {
        this.orderRepository  = orderRepository;
        this.sagaOrchestrator = sagaOrchestrator;
    }

    /**
     * Creates an order and immediately starts the saga.
     *
     * Note: @Transactional intentionally NOT used here.
     * The saga makes external HTTP calls (payment service) inside it.
     * Holding a DB transaction open across network calls causes
     * connection pool exhaustion under load.
     */
    public Order createOrder(String username, CreateOrderRequest req) {
        // Validate input
        if (req.getProductName() == null || req.getProductName().isBlank())
            throw new IllegalArgumentException("Product name is required");
        if (req.getQuantity() == null || req.getQuantity() <= 0)
            throw new IllegalArgumentException("Quantity must be greater than 0");
        if (req.getAmount() == null || req.getAmount().signum() <= 0)
            throw new IllegalArgumentException("Amount must be greater than 0");

        // Step 1: persist order as PENDING
        Order order = new Order();
        order.setUsername(username);
        order.setProductName(req.getProductName().trim());
        order.setQuantity(req.getQuantity());
        order.setAmount(req.getAmount());
        order.setStatus(OrderStatus.PENDING);
        orderRepository.save(order);

        // Hand off to saga orchestrator — drives steps 2 and 3
        return sagaOrchestrator.executeSaga(order);
    }

    public List<Order> getMyOrders(String username) {
        return orderRepository.findByUsername(username);
    }

    public Optional<Order> getOrderById(Long id, String username) {
        return orderRepository.findByIdAndUsername(id, username);
    }

    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }
}
