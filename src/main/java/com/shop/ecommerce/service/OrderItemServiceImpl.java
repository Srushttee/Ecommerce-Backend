package com.shop.ecommerce.service;

import com.shop.ecommerce.model.OrderItem;
import com.shop.ecommerce.repository.OrderItemRepository;
import org.springframework.stereotype.Service;

@Service
public class OrderItemServiceImpl implements OrderItemService {
    private OrderItemRepository orderItemRepository;

    @Override
    public OrderItem createOrderItem(OrderItem orderItem) {
        return orderItemRepository.save(orderItem);
    }
}
