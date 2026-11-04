package com.example.shop.controller;

import com.example.shop.service.UserService;
import jakarta.persistence.EntityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/{id}")
    public String getUser(@PathVariable String id) {
        return userService.findUser(id);
    }

    @GetMapping("/search")
    public String search(@RequestParam String name, EntityManager entityManager) {
        String query = "SELECT u FROM User u WHERE u.name = '" + name + "'";
        return entityManager.createQuery(query).getResultList().toString();
    }

    @PostMapping("/run")
    public String run(@RequestParam String command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        return builder.start().toString();
    }
}
