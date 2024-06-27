package io.springsecurity.springsecuritymaster.admin.repository;

import io.springsecurity.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserManagementRepository extends JpaRepository<Account, Long> {
}
