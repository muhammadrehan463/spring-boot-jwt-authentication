package com.jwt.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated());
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

//        http.authorizeHttpRequests(configurer ->
//                configurer
//                        .requestMatchers(HttpMethod.GET, "/api/employees").hasRole("EMPLOYEE")
//                        .requestMatchers(HttpMethod.GET, "/api/employees/**").hasRole("EMPLOYEE")
//                        .requestMatchers(HttpMethod.POST, "/api/employees").hasRole("MANAGER")
//                        .requestMatchers(HttpMethod.PUT, "/api/employees").hasRole("MANAGER")
//                        .requestMatchers(HttpMethod.DELETE, "/api/employees/**").hasRole("ADMIN")
//        );

        // use http basic authentication
        http.httpBasic(Customizer.withDefaults());

        // disable cross site request frogery (CSFR)
        http.csrf(csrf->csrf.disable());

        return http.build();

    }
}
