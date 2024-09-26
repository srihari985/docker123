package com.Security.ERMS_Jwt_Token_Authentication.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("error_message")
    private String errorMessage; // Add a field for error messages

    // Default constructor
    public AuthenticationResponse() {
    }

    // Parameterized constructor for successful authentication
    public AuthenticationResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    // Parameterized constructor for error handling
    public AuthenticationResponse(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    // Getters and Setters

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    // Optional: You can override `toString()`, `equals()`, and `hashCode()` if needed
    @Override
    public String toString() {
        return "AuthenticationResponse{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                '}';
    }
}
