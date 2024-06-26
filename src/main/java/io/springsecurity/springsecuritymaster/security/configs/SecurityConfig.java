package io.springsecurity.springsecuritymaster.security.configs;

import io.springsecurity.springsecuritymaster.security.dsl.RestApiDsl;
import io.springsecurity.springsecuritymaster.security.entrypoint.RestAuthenticationEntryPoint;
import io.springsecurity.springsecuritymaster.security.handler.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationProvider restAuthenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler successHandler;
    private final FormAuthenticationFailureHandler failureHandler;
    private final RestAuthenticationSuccessHandler restSuccessHandler;
    private final RestAuthenticationFailureHandler restFailureHandler;
    private final AuthorizationManager<RequestAuthorizationContext> authorizationManager;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().access(authorizationManager))
                .formLogin(form -> form
                        .loginPage("/login").permitAll()
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .successHandler(successHandler)
                        .failureHandler(failureHandler))
                .authenticationProvider(authenticationProvider)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(new FormAccessDeniedHandler("/denied")));
        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(restAuthenticationProvider);
        AuthenticationManager authenticationManager = builder.build();

        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .requestMatchers("/api", "/api/login").permitAll()
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/manager").hasAuthority("ROLE_MANAGER")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll())
//                .csrf(AbstractHttpConfigurer::disable)
                .authenticationManager(authenticationManager)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler()))
                .with(new RestApiDsl<>(), restDsl -> restDsl
                        .restSuccessHandler(restSuccessHandler)
                        .failureHandler(restFailureHandler)
                        .loginPage("/api/login")
                        .loginProcessingUrl("/api/login"));
        return http.build();
    }
}
