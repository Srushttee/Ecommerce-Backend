package com.shop.ecommerce.exception;

import com.shop.ecommerce.model.User;

public class UserException extends Exception{
    public UserException(String message){
        super(message);
    }
}
