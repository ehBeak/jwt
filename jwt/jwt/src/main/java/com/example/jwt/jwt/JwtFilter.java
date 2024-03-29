package com.example.jwt.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/* jwt를 위한 커스텀 필터를 만들기 위해 클래스 생성*/
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private TokenProvider tokenProvider;

    // 이 클래스는 tokenProvider을 주입받음
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    // extends한 GenericFilterBean의 doFilter을 오버라이드
    // 토큰의 인증 정보를 SecurityContext에 저장하는 역할 수행
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest; // 요청객체
        String jwt = resolveToken(httpServletRequest); // 요청객체에서 토큰 받음
        String requestURI = httpServletRequest.getRequestURI();

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { // 받은 토큰을 유효성 검사 함수를 통해 유효성 검사함
            Authentication authentication = tokenProvider.getAuthentication(jwt); // 토큰이 정상적이면 autentication객체에서 토큰 받와서
            SecurityContextHolder.getContext().setAuthentication(authentication); // securityContext에 set해줌
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        // 다음 필터 처리
        filterChain.doFilter(servletRequest, servletResponse);
    }

    // 필터링을 하기 위해서 토큰 정보가 있어야하니까
    // Request Header에서 토큰 정보를 꺼내오기 위한 resolveToken메소드 추가
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
