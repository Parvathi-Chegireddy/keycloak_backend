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

    public Order createOrder(String username, CreateOrderRequest req) {
        // Validate input
        if (req.getProductName() == null || req.getProductName().isBlank())
            throw new IllegalArgumentException("Product name is required");
        if (req.getQuantity() == null || req.getQuantity() <= 0)
            throw new IllegalArgumentException("Quantity must be greater than 0");
        if (req.getAmount() == null || req.getAmount().signum() <= 0)
            throw new IllegalArgumentException("Amount must be greater than 0");

        Order order = new Order();
        order.setUsername(username);
        order.setProductName(req.getProductName().trim());
        order.setQuantity(req.getQuantity());
        order.setAmount(req.getAmount());
        order.setStatus(OrderStatus.PENDING);
        orderRepository.save(order);

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
