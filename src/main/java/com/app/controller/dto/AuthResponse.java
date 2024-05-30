package com.app.controller.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username","message","jwt","status"})//orden de respuesta
public record AuthResponse(String username,
                           String message ,
                           String jwt ,
                           boolean status) {


}
