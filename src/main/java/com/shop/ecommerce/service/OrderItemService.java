package com.shop.ecommerce.service;

import com.shop.ecommerce.model.OrderItem;
import org.springframework.stereotype.Service;

@Service
public interface OrderItemService {
    OrderItem createOrderItem(OrderItem orderItem);
}
