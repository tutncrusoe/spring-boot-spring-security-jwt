package com.example.springsecurityjwt.repository;

import java.util.Optional;

import com.example.springsecurityjwt.models.ERole;
import com.example.springsecurityjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
