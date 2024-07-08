package io.security.oauth2.springsecurityoauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String scopes = jwt.getClaimAsString("scope");
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

        if (scopes != null || realmAccess != null) {
            return Collections.EMPTY_LIST;
        }

        List<GrantedAuthority> authorities1 = Arrays.stream(scopes.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        List<GrantedAuthority> authorities2 = ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities2.addAll(authorities1);
        return authorities2;
    }
}
