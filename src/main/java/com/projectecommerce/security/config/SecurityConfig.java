package com.projectecommerce.security.config;

import com.projectecommerce.security.jwt.JWTAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTAuthFilter jwtAuthFilter;
    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/verify", "/api/auth/profile", "/api/auth/change-password").hasAnyRole("ADMIN", "SALES", "CUSTOMER")

                        .requestMatchers(HttpMethod.DELETE, "/api/users/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/users/{id}/status").hasRole("ADMIN")
                        .requestMatchers("/api/users/{id}/**").hasAnyRole("ADMIN", "SALES")
                        .requestMatchers("/api/users/**").hasAnyRole("ADMIN", "SALES")

                        .requestMatchers(HttpMethod.GET, "/api/categories").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/categories").hasAnyRole("ADMIN", "SALES")
                        .requestMatchers(HttpMethod.PUT, "/api/categories/{id}").hasAnyRole("ADMIN", "SALES")
                        .requestMatchers(HttpMethod.DELETE, "/api/categories/{id}").hasRole("ADMIN")

                        .anyRequest().authenticated()
                )

                .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

}