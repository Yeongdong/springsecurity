package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/home")
    public String home(Model model, OAuth2AuthenticationToken oauth2AuthenticationToken) {
        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient("keycloak", oauth2AuthenticationToken.getName());

        model.addAttribute("oauth2AuthenticationToken", oauth2AuthenticationToken);
        model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
        if (authorizedClient.getRefreshToken() != null) {
            model.addAttribute("refreshToken", authorizedClient.getRefreshToken().getTokenValue());
        }


        return "home";
    }
}
