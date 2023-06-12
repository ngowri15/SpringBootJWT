package com.alphanove.springboot_security.repository;

import com.alphanove.springboot_security.entity.Roles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RolesRepository extends JpaRepository<Roles, Integer> {
    Optional<Roles> findByName(String name);
}
