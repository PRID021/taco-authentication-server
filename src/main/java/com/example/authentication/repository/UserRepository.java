package com.example.authentication.repository;


import org.springframework.data.repository.CrudRepository;

import com.example.authentication.models.TacoUser;

public interface UserRepository extends CrudRepository<TacoUser, Long> {
    TacoUser findByUserName(String username);
}
