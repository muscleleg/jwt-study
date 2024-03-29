package com.jj.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jj.jwt.config.auth.PrincipalDetails;
import com.jj.jwt.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSourceAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

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
        // /login에 requestBody로 전송하면됨
        //1. username, password를 받음
        //2. authenticationManger로 로그인을 시도하면 PrincipalDetailsService가 호출됨 -> loadUserByUsername() 함수가 실행됨

        //3.principalDetails를 세션에 담고 principalDetails을 세션에 안 담으면 권한관리가 안됨, 권한 관리를 위해서
        //4. JWT토큰을 만들어서 응답해주면 됨
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);
            //시큐리티가 알아서 비밀번호 찾아서 검증
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //authentication 객체가 session영역에 저장됨 -> 로그인이 되었다는 뜻
            //내 로그인한 정보가 담김
            Authentication authentication = authenticationManager.authenticate(authenticationToken);//PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨:" + principalDetails.getUser().getUsername());

            //authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면됨
            //리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
            //굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음 , 근데 단지 권한 처리때문에 session 넣어줌
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    //JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식 아님, Hash 암호 방식
        String jwtToken = JWT.create().withSubject(principalDetails.getPassword())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUsername())
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader("Authorization", "Bearer " + jwtToken);
        // 쿠키방식
        // 유저네임, 패스워드 로그인 정상
        // 서버쪽 세션ID 생성
        // 클라이언트 쿠키 세션 ID를 응답
        // 요청할 때마다 쿠키값 세션ID를 항상 들고 서버쪽으로 요청하기 때문에
        // session.getAttribute
        // 서버는 세션ID가 유효한지 판단해서 유효하면 인증이 필요한 페이지로 접근하게 하면 됨


        //JWT
        //유저네임, 패스워드 로그인 정상
        //JWT 토큰을 생성
        //클라이언트 쪽으로 JWT토큰을 응답

        //요청할 때마다 JWT토큰을 가지고 요청
        //서버는 JWT 토큰이 유효한지를 판단(필터를 만들어야함)

        System.out.println("successfulAuthentication 실행됨 : 인증이완료되었다는 뜻임");
    }
}
