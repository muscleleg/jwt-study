package com.jj.jwt.config;

import com.jj.jwt.config.jwt.JwtAuthenticationFilter;
import com.jj.jwt.config.jwt.JwtAuthorizationFilter;
import com.jj.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CorsConfigurationSource corsConfigurationSource;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors((cors) -> cors
                        .configurationSource(corsConfigurationSource)
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션을 사용하지 않겠다.
                .formLogin(AbstractHttpConfigurer::disable) // 폼 로그인
                .httpBasic(AbstractHttpConfigurer::disable) //헤더에 id pwd 넣어서 보내는것
                .addFilter(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationConfiguration.getAuthenticationManager(),userRepository))
                .authorizeHttpRequests((request) ->
                        request
                                .requestMatchers("/api/v1/user/**").authenticated()
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                )
//                .formLogin(login->login.defaultSuccessUrl("/")) 해당 옵션 없으면 기본 security login form 안나옴
                .build();
    }


}
