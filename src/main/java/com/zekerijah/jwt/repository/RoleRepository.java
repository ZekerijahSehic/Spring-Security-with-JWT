package com.zekerijah.jwt.repository;

import com.zekerijah.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
