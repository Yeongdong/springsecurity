package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@Controller
public class IndexController {
    @GetMapping("/")
    public Authentication index(Authentication authentication, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {

        BearerTokenAuthentication authenticationToken = (BearerTokenAuthentication) authentication;
        Map<String, Object> tokenAttributes = authenticationToken.getTokenAttributes();
        boolean active = (boolean) tokenAttributes.get("active");
        OpaqueDto opaqueDto = new OpaqueDto();
        opaqueDto.setActive(active);
        opaqueDto.setAuthentication(authentication);
        opaqueDto.setPrincipal(principal);

        return authentication;
    }
}
