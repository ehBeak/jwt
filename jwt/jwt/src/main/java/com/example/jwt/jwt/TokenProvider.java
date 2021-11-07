package com.example.jwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;


    public TokenProvider( // 빈 주입
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    // initalizingBean의 함수 afterPropertiesSet()을 오버라이드 함
    /* 이유
    *  빈이 생성이 되고 주입을 받은 후에 secret값을 Base64 Decode해서
    *  key 변수에 할당하기 위함 */
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret); // 디코딩
        this.key = Keys.hmacShaKeyFor(keyBytes); // 키변수에 할당
    }

    // authentication객체의 권한정보를 이용해서 토큰을 생성하는 함수
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream() // 권한 설정
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime(); // 만료 시간 설정
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact(); // 토큰 생성 후 리턴
    }

    // token에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메소드
    public Authentication getAuthentication(String token) { // 토큰을 파라미터로 바꿈
        Claims claims = Jwts // 받은 토큰으로 클레임을 만듦
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities = // 클레임에서 권한 정보 빼냄
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // 권한 정보를 이용해 user객체 생성
        User principal = new User(claims.getSubject(), "", authorities);

        // user객체와 토큰 그리고 권한 정보를 이용하여 최종적으로 Authentication객체를 리턴
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰을 받아서 토큰의 유효성 검증을 수행하는 메소드
    public boolean validateToken(String token) {
        try { // 토큰을 받아서 파싱해보고
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true; // 문제 없으면 true 반환
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false; // 문제 있으면 false 반환
    }
}