package com.ys.jwtexample.controller;

import com.ys.jwtexample.config.jwt.JwtTokenProvider;
import com.ys.jwtexample.entitiy.User;
import com.ys.jwtexample.entitiy.Role;
import com.ys.jwtexample.entitiy.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // 회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> user) {
        return userRepository.save(User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .role(Role.USER)
                .build()).getId();
    }

    // 로그인
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> user) {

        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(() -> new IllegalArgumentException("가입 되지 않은 EMAIL 입니다"));

        if (!passwordEncoder.matches(user.get("password"), member.getPassword()))
            throw new IllegalArgumentException("잘못된 비밀번호 입니다");

        String token = jwtTokenProvider.createToken(member.getEmail(), member.getRole());
        System.out.println("token = " + token);
        return token;
    }

    @GetMapping("/test")
    public List<User> test() {
        System.out.println("test!!");
        return userRepository.findAll();
    }


    @GetMapping("/api/user/users")
    public List<User> simpleApiRequest() {
        System.out.println("UserController.ok");
        return userRepository.findAll();
    }

}
