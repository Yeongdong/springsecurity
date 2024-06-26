package io.springsecurity.springsecuritymaster.users.service;

import io.springsecurity.springsecuritymaster.admin.repository.RoleRepository;
import io.springsecurity.springsecuritymaster.domain.entity.Account;
import io.springsecurity.springsecuritymaster.domain.entity.Role;
import io.springsecurity.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Transactional
    public void createUser(Account account) {
        Role role = roleRepository.findByRoleName("ROLE_USER");
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        account.setUserRoles(roles);
        userRepository.save(account);
    }
}
