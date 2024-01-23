package com.jj.jwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter
//login 요청해서 username, password 전송하면 UsernamePasswordAuthenticationFilter 필터가 작동함
//현재는 formLogin을 disable해서 작동을 안함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");
        //1. username, password를 받음
        //2. authenticationManger로 로그인을 시도하면 PrincipalDetailsService가 호출됨 -> loadUserByUsername() 함수가 실행됨

        //3.principalDetails를 세션에 담고 principalDetails을 세션에 안 담으면 권한관리가 안됨, 권한 관리를 위해서
        //4. JWT토큰을 만들어서 응답해주면 됨
        return super.attemptAuthentication(request, response);
    }
}
