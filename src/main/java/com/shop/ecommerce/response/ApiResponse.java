package com.shop.ecommerce.response;

public class ApiResponse {

    private boolean status;
    private String message;

    public ApiResponse() {
    }

    public ApiResponse(boolean status, String message) {
        this.status = status;
        this.message = message;
    }

    // Getter for status
    public boolean isStatus() {
        return status;
    }

    // Setter for status
    public void setStatus(boolean status) {
        this.status = status;
    }

    // Getter for message
    public String getMessage() {
        return message;
    }

    // Setter for message
    public void setMessage(String message) {
        this.message = message;
    }

}
