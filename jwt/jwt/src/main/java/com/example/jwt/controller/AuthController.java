package com.example.jwt.controller;

import com.example.jwt.dto.LoginDto;
import com.example.jwt.dto.TokenDto;
import com.example.jwt.jwt.JwtFilter;
import com.example.jwt.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    // tokenProvider, AuthenticationManagerBuilder로 주입받음
    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    // 이건 DB에 저장되어있는 정보를 통해 새로운 토큰을 제공하는 것임
    // 사용자의 username과 password를 보내면 토큰을 생성해서 리턴해줌(username, password)
    @PostMapping("/authenticate") // /api/authenticate
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        // 1. loginDto로 username과 password를 받아서 authenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        // 2. authenticationToken을 이용해서 authentication을 생성
        // 3. 이때 loadUserByUsername메소드 실행 : DB에서 유저정보와 권한정보 가져옴
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        // 4. authentication을 securityContext에 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 5. authentication객체를 createToken을 사용하여 jwtToken을 생성함
        String jwt = tokenProvider.createToken(authentication);

        // 6. jwt토큰을 header에 넣어줌
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        // 7. TokenDto를 이용해서 responseBody에도 넣고 리턴함.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
