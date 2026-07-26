package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.RateLimitService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final AuditService auditService;

    private final CustomAuthenticationFailureHandler failureHandler;

    private final CustomAuthenticationSuccessHandler successHandler;

    private final CustomLogoutSuccessHandler logoutSuccessHandler;

    private final RateLimitService rateLimitService;

    public SecurityConfig(AuditService auditService,
                          CustomAuthenticationFailureHandler failureHandler,
                          CustomAuthenticationSuccessHandler successHandler,
                          CustomLogoutSuccessHandler logoutSuccessHandler,
                          RateLimitService rateLimitService) {
        this.auditService = auditService;
        this.failureHandler = failureHandler;
        this.successHandler = successHandler;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.rateLimitService = rateLimitService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter(), UsernamePasswordAuthenticationFilter.class)

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/",
                                "/login",
                                "/register",
                                "/login/2fa",
                                "/login/2fa/verify",
                                "/css/**",
                                "/js/**",
                                "/favicon.ico",
                                "/.well-known/**",
                                "/error/**")
                        .permitAll()
                        .requestMatchers("/api/password/generate").authenticated()
                        .requestMatchers("/api/session/**").authenticated()
                        .requestMatchers("/settings/**").authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .sessionRegistry(sessionRegistry())

                )

                .csrf(Customizer.withDefaults())

                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; " +
                                        "script-src 'self' 'unsafe-inline'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self';"
                                )
                        )
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .xssProtection(HeadersConfigurer.XXssConfig::disable)
                        .contentTypeOptions(contentTypeOptions -> {})
                );

        return http.build();
    }

    @Bean
    public RateLimitingFilter rateLimitingFilter() {
        return new RateLimitingFilter(auditService, rateLimitService);
    }

    @Bean
    public org.springframework.security.core.session.SessionRegistry sessionRegistry() {
        return new org.springframework.security.core.session.SessionRegistryImpl();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPasswordHash())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found: "+username));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
