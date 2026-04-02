package com.spantag.order_service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    /**
     * POST /api/orders
     * Creates an order and runs the saga.
     * Returns 201 CREATED for CONFIRMED orders.
     * Returns 200 OK with status=CANCELLED for saga-compensated orders
     * (so the frontend can display the cancellation reason).
     */
    @PostMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<OrderResponse> createOrder(
            Principal principal,
            @RequestBody CreateOrderRequest req) {
        try {
            Order order = orderService.createOrder(principal.getName(), req);

            if (order.getStatus() == OrderStatus.CANCELLED) {
                // Return 200 with CANCELLED status — frontend shows the reason
                // (422 would cause axios to throw, making the message harder to show)
                return ResponseEntity.ok(OrderResponse.from(order));
            }

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(OrderResponse.from(order));

        } catch (IllegalArgumentException e) {
            OrderResponse err = new OrderResponse();
            err.setMessage(e.getMessage());
            return ResponseEntity.badRequest().body(err);
        }
    }

    /**
     * GET /api/orders
     * Returns all orders belonging to the authenticated user.
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<OrderResponse>> getMyOrders(Principal principal) {
        List<OrderResponse> orders = orderService.getMyOrders(principal.getName())
                .stream().map(OrderResponse::from).toList();
        return ResponseEntity.ok(orders);
    }

    /**
     * GET /api/orders/{id}
     * Returns a specific order — only if it belongs to the caller.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<OrderResponse> getOrder(
            @PathVariable Long id,
            Principal principal) {
        return orderService.getOrderById(id, principal.getName())
                .map(o -> ResponseEntity.ok(OrderResponse.from(o)))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).<OrderResponse>build());
    }

    /**
     * GET /api/orders/admin/all
     * Admin only — returns all orders across all users.
     */
    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<OrderResponse>> getAllOrders() {
        List<OrderResponse> orders = orderService.getAllOrders()
                .stream().map(OrderResponse::from).toList();
        return ResponseEntity.ok(orders);
    }
}
