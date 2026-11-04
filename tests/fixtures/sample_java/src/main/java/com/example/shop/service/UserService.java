package com.example.shop.service;

import com.example.shop.model.User;
import com.example.shop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public String findUser(String id) {
        User user = userRepository.findById(id).orElse(null);
        return user == null ? "" : user.getName();
    }

    public long countUsers() {
        return userRepository.count();
    }
}
