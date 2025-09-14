package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Review;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.request.ReviewRequest;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface ReviewService {
    Review createReview(ReviewRequest req, User user) throws ProductException;

    List<Review> getAllReview(Long productId);
}
