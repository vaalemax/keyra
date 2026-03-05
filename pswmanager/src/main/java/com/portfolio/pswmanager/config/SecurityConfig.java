package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomAuthenticationSuccessHandler successHandler;
    private final CustomAuthenticationFailureHandler failureHandler;
    private final CustomLogoutSuccessHandler logoutSuccessHandler;
    private final RateLimitingFilter rateLimitingFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeHttpRequests(auth -> auth.
                        requestMatchers("/", "/login", "/register", "/login/2fa", "/login/2fa/verify", "/css/**", "/js/**", "/h2-console/**", "/error/**").permitAll()
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
                        .sessionFixation().migrateSession()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )

                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**")
                )

                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        return http.build();
    }

    /**
     *
     * Definisce le regole di accesso:
     * java.requestMatchers("/", "/login", "/register").permitAll()  // ✅ Chiunque
     * .requestMatchers("/vault/**").authenticated()              // 🔒 Solo loggati
     * .requestMatchers("/admin/**").hasRole("ADMIN")            // 👑 Solo admin
     * .anyRequest().authenticated()                              // 🔒 Default: protetto
     * Order matters! Le regole vengono valutate dall'alto verso il basso.
     */

    /**
     *
     * 3. formLogin
     * java.loginPage("/login")              // Il tuo template Thymeleaf
     * .loginProcessingUrl("/login")     // Spring intercetta POST /login
     * .defaultSuccessUrl("/vault", true)
     * Come funziona il form:
     * Il tuo login.html deve avere:
     * html<form th:action="@{/login}" method="post">
     *     <input type="text" name="username" />      <!-- DEVE chiamarsi "username" -->
     *     <input type="password" name="password" />  <!-- DEVE chiamarsi "password" -->
     *     <button type="submit">Login</button>
     * </form>
     *
     * Spring Security:
     *
     * Intercetta il POST a /login
     * Estrae username e password dai parametri
     * Chiama UserDetailsService
     * Valida con PasswordEncoder
     * Redirect a /vault se OK, /login?error se KO
     */


    /**
     * 4. logout
     * java.logoutUrl("/logout")                          // POST /logout
     * .logoutSuccessUrl("/login?logout=true")        // Redirect dopo logout
     * .invalidateHttpSession(true)                   // Cancella session
     * Nel tuo template:
     * html<form th:action="@{/logout}" method="post">
     *     <button type="submit">Logout</button>
     * </form>
     */

    /**
     *
     * 5. CSRF Protection
     * Di default Spring Security richiede CSRF token in tutti i POST.
     * Thymeleaf lo aggiunge automaticamente nei form:
     * html<form th:action="@{/login}" method="post">
     *     <!-- Thymeleaf aggiunge automaticamente questo: -->
     *     <input type="hidden" name="_csrf" value="..." />
     * </form>
     * Se usi fetch/axios, devi includerlo manualmente:
     * javascriptfetch('/api/endpoint', {
     *     method: 'POST',
     *     headers: {
     *         'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]').content
     *     }
     * })
     */






    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPasswordHash())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    /*
    Questo è il ponte tra il tuo DB e Spring Security.
        Cosa fa:
        javausername → UserRepository.findByUsername(username)
         → converte User entity in UserDetails (oggetto che Security capisce)
         → ritorna UserDetails con username + passwordHash

         Perché serve:
            Quando fai login, Spring Security:

            Prende username dal form
            Chiama userDetailsService.loadUserByUsername(username)
            Ottiene UserDetails con il password hash
            Compara passwordEncoder.matches(passwordForm, passwordHashDB)
            Se match → login OK → crea sessione
     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
