package com.app.persistence.entity;


import jakarta.persistence.*;
import lombok.*;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "permissions")

public class PermissionEntity {
    @Id
    @GeneratedValue( strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true , nullable = false, updatable = false)
    private String name;

}
