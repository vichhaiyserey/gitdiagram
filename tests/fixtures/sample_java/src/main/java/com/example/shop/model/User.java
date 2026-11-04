package com.example.shop.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class User {

    @Id
    private String id;

    private String name;

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
