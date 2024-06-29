package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.
                authorizeRequests(authorized -> authorized
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .with(new CustomSecurityConfigurer().setFlag(true), Customizer.withDefaults());
        return http.build();
    }
}
