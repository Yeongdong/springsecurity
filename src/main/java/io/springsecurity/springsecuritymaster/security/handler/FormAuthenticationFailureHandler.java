package io.springsecurity.springsecuritymaster.security.handler;

import io.springsecurity.springsecuritymaster.security.exception.SecretException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class FormAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invalid Username or Password";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if (exception instanceof UsernameNotFoundException) {
            errorMessage = "Username not found";
        } else if (exception instanceof CredentialsExpiredException) {
            errorMessage = "Password expired";
        } else if (exception instanceof SecretException) {
            errorMessage = "Invalid secret key";
        }
        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);    // 컨트롤러에서 해당 요청에 대한 처리를 해주어야한다.
        super.onAuthenticationFailure(request, response, exception);
    }
}
