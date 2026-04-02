package com.spantag.order_service;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OrderRepository extends JpaRepository<Order, Long> {
    List<Order> findByUsername(String username);
    List<Order> findByUsernameAndStatus(String username, OrderStatus status);
    Optional<Order> findByIdAndUsername(Long id, String username);
}