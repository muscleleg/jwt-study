package com.jj.config;

import org.apache.catalina.filters.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {
    @Bean
    public CorsConfigurationSource corsConfiguration() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); //요청이 인증 정보를 포함하고 있을 때 해당 정보를 허용할지 여부를 설정합니다.
        config.addAllowedOrigin("*"); // 허용할 오리진을 설정합니다.
        config.addAllowedHeader("*"); // 허용할 HTTP 메서드를 설정합니다.
        config.addAllowedMethod("*"); // 허용할 HTTP 메서드를 설정합니다.

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
