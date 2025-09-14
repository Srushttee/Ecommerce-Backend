package com.shop.ecommerce.controller;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.exception.UserException;
import com.shop.ecommerce.model.Review;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.request.ReviewRequest;
import com.shop.ecommerce.service.ReviewService;
import com.shop.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reviews")
public class ReviewController {

    @Autowired
    private UserService userService;

    @Autowired
    private ReviewService reviewService;

    @PostMapping("/create")
    public ResponseEntity<Review> createReview(@RequestBody ReviewRequest req,
                                               @RequestHeader("Authorization") String jwt) throws UserException, ProductException {
        User user = userService.findUserProfileByJwt(jwt);
        Review review = reviewService.createReview(req, user);

        return new ResponseEntity<Review>(review, HttpStatus.CREATED);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<List<Review>> getProductsRating(@PathVariable Long productId,
                                                          @RequestHeader("Authorization") String jwt) throws UserException, ProductException {
        User user = userService.findUserProfileByJwt(jwt);

        List<Review> reviews = reviewService.getAllReview(productId);

        return new ResponseEntity<>(reviews, HttpStatus.ACCEPTED);
    }

}
