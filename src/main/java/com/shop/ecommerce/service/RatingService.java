package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Rating;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.request.RatingRequest;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface RatingService {

    Rating createRating(RatingRequest req, User user) throws ProductException;

    List<Rating> getProductsRating(Long productId);
}
