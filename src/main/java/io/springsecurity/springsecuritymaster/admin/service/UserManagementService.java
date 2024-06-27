package io.springsecurity.springsecuritymaster.admin.service;

import io.springsecurity.springsecuritymaster.domain.dto.AccountDto;
import io.springsecurity.springsecuritymaster.domain.entity.Account;

import java.util.List;

public interface UserManagementService {
    void modifyUser(AccountDto accountDto);

    List<Account> getUsers();

    AccountDto getUser(Long id);

    void deleteUser(Long idx);
}
