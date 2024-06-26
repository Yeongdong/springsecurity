package io.springsecurity.springsecuritymaster.admin.repository;

import io.springsecurity.springsecuritymaster.domain.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByRoleName(String roleUser);
}
