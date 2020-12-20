package com.ys.jwtexample.config;


import com.ys.jwtexample.config.jwt.JwtAuthenticationFilter;
import com.ys.jwtexample.config.jwt.JwtTokenProvider;
import com.ys.jwtexample.entitiy.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("WebSecurityConfig.configure");
        http
                .httpBasic().disable() // rest api만을 고려하여 기본 설정 해제
                .csrf().disable() // csrf 보안 토큰 disable

                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 토큰 기반 인증이므로 세션 역시 사용하지 않습니
                .and()
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), jwtTokenProvider))
                .authorizeRequests() // 요청 권한에 대한 사용 권한 체크
                    .antMatchers("/api/user/**").hasRole(Role.USER.name())
                    .antMatchers("/api/admin/**").hasRole(Role.ADMIN.name())
                .anyRequest().permitAll();

    }

}
