package io.springsecurity.springsecuritymaster.security.service;

import io.springsecurity.springsecuritymaster.security.mapper.UrlRoleMapper;

import java.util.Map;

public class DynamicAuthorizationService {

    private final UrlRoleMapper delegate;

    public DynamicAuthorizationService(UrlRoleMapper delegate) {
        this.delegate = delegate;
    }

    public Map<String, String> getUrlRoleMappings() {
        return delegate.getUrlRoleMappings();
    }
}
