package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ResourceServerConfig {

    @Autowired
    private OAuth2ResourceServerProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oAuth2ResourceServerConfig -> oAuth2ResourceServerConfig.jwt(Customizer.withDefaults()))
        ;
        return http.build();
    }

//    @Bean
//    public JwtDecoder jwtDecoder1() {
//        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
//    }
//    @Bean
//    public JwtDecoder jwtDecoder2() {
//        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
//    }

    @Bean
    public JwtDecoder jwtDecoder3() {
        return NimbusJwtDecoder.withJwkSetUri(this.properties.getJwt().getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
    }
}
