package com.alphanove.springboot_security.repository;



import com.alphanove.springboot_security.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<Users, Integer> {
    Optional<Users> findByUsername(String username);
    Boolean existsByUsername(String username);
}