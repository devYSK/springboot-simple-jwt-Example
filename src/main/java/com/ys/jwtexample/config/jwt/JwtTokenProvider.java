package com.ys.jwtexample.config.jwt;

import com.ys.jwtexample.entitiy.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@RequiredArgsConstructor
@Component
public class JwtTokenProvider {

    private static String secretKey = "secretKey";
    private static final String AUTHORIZATION_HEADER = "x-auth-token";

    private final long tokenValidTime = 30 * 60 * 1000L; //60분

    private final UserDetailsService userDetailsService;

//    @PostConstruct
//    protected void init() {
//        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
//    }

    public String createToken(String userPk, Role role) {
        System.out.println("JwtTokenProvider.createToken");
        Claims claims = Jwts.claims().setSubject(userPk); // payload에 저장되는 정보 단위

        claims.put("roles", role); // key/value로 저장됨

        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now) // 토큰 발행 시간
                .setExpiration(new Date(now.getTime() + tokenValidTime)) // 토큰 유효 시간
                .signWith(SignatureAlgorithm.HS256, secretKey) // 사용할 알고리즘과 시그니처에 들어갈 값
                .compact();
    }

    //JWT토큰에서 인증정보 조회
    public Authentication getAuthentication(String token) {
        System.out.println("JwtTokenProvider.getAuthentication");
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUsernameFromToken(token));

        return new UsernamePasswordAuthenticationToken(userDetails,
                 "",
                userDetails.getAuthorities());
    }

    private String getUsernameFromToken(String token) {
        System.out.println("JwtTokenProvider.getUsernameFromToken");
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        System.out.println("JwtTokenProvider.getTokenFromRequest");
        return request.getHeader(AUTHORIZATION_HEADER);
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        System.out.println("JwtTokenProvider.validateToken");
        Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
        return !claims.getBody().getExpiration().before(new Date());
    }

}
