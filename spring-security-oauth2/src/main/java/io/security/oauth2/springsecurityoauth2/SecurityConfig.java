package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http.
                authorizeHttpRequests(authorized -> authorized
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
//                .with(new CustomSecurityConfigurer().setFlag(true), Customizer.withDefaults());
        return http.build();
    }

    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.
                authorizeHttpRequests(authorized -> authorized
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());
//                .with(new CustomSecurityConfigurer().setFlag(true), Customizer.withDefaults());
        return http.build();
    }
}
