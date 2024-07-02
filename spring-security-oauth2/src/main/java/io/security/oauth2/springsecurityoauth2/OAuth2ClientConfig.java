package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/loginPage").permitAll()
                        .anyRequest().authenticated())
//                .oauth2Login(login -> login
//                        .loginPage("/loginPage")
//                )
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }
}
