package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

@Data
@NoArgsConstructor
@Entity
@Table(name = "actions")
public class Action {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;
}
