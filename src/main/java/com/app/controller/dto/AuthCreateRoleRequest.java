package com.app.controller.dto;

//este record que seria para la creacion de los roles
//simplemente necesitamos enviar la lista de los roles
//por que el userEntity recibe una lista de roles
//y el rol tendria solamente el nombre

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

import java.util.List;

//definimos la lista de roles
@Validated
public record AuthCreateRoleRequest(
        @Size(max = 3, message ="The user cannot have more than 3 roles" ) List<String> roleListName ) {
}
