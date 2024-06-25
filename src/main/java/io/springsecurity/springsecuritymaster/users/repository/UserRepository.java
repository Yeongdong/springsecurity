package io.springsecurity.springsecuritymaster.users.repository;

import io.springsecurity.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
