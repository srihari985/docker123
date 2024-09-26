package com.Security.ERMS_Jwt_Token_Authentication.Orgnization;


import com.fasterxml.jackson.annotation.JsonProperty;

public class OrganizationResponse {

    @JsonProperty("message")
    private String message;

    // Constructor with message
    public OrganizationResponse(String message) {
        this.message = message;
    }

    // Default constructor
    public OrganizationResponse() {
    }

    // Getter and Setter for message
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
