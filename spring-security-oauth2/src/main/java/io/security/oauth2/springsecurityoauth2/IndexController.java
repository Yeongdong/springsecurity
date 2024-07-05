package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
    @GetMapping("/")
    public Authentication index(Authentication authentication) {
        return authentication;
    }
}
