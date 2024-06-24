package io.springsecurity.springsecuritymaster;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.List;
import java.util.function.Supplier;

public class CustomRequestMatcherDelegatingAuthorizationManger implements AuthorizationManager<RequestAuthorizationContext> {

    RequestMatcherDelegatingAuthorizationManager manager;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        return manager.check(authentication, object.getRequest());
    }

    public CustomRequestMatcherDelegatingAuthorizationManger(List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
        manager = RequestMatcherDelegatingAuthorizationManager.builder().mappings(maps -> maps.addAll(mappings)).build();
    }
}
