package io.springsecurity.springsecuritymaster.security.service;

import io.springsecurity.springsecuritymaster.domain.dto.AccountDto;
import io.springsecurity.springsecuritymaster.domain.entity.Account;
import io.springsecurity.springsecuritymaster.domain.entity.Role;
import io.springsecurity.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service("userDetailService")
@RequiredArgsConstructor
public class FormUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByUsername(username);

        if (account == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        List<GrantedAuthority> authorities = account.getUserRoles()
                .stream()
                .map(Role::getRoleName)
                .collect(Collectors.toSet())
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        ModelMapper modelMapper = new ModelMapper();
        AccountDto accountDto = modelMapper.map(account, AccountDto.class);

        return new AccountContext(accountDto, authorities);
    }
}
