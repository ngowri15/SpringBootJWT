package com.alphanove.springboot_security.controller;


import com.alphanove.springboot_security.dto.AuthResponseDto;
import com.alphanove.springboot_security.dto.LoginDto;
import com.alphanove.springboot_security.dto.RefreshTokenDto;
import com.alphanove.springboot_security.dto.RegisterDto;
import com.alphanove.springboot_security.entity.Roles;
import com.alphanove.springboot_security.entity.Users;
import com.alphanove.springboot_security.repository.RolesRepository;
import com.alphanove.springboot_security.repository.UserRepository;
import com.alphanove.springboot_security.security.JWTGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RolesRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private JWTGenerator jwtGenerator;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository,
                          RolesRepository roleRepository, PasswordEncoder passwordEncoder, JWTGenerator jwtGenerator) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtGenerator = jwtGenerator;
    }

    @PostMapping("login")
    public ResponseEntity<AuthResponseDto> login(HttpServletRequest request, @RequestBody LoginDto loginDto) {


        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.getUsername(),
                        loginDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtGenerator.generateAccessToken(authentication);
        String refreshToken = jwtGenerator.generateRefreshToken(authentication);

       /*

        request.getSession().setAttribute("username",loginDto.getUsername());
        request.getSession().setAttribute("password",loginDto.getPassword());

        request.getSession().setAttribute("accessToken", accessToken);
        request.getSession().setAttribute("refreshToken", refreshToken);

        System.out.println("Session access token from login controller " + request.getSession().getAttribute("accessToken"));
        System.out.println("Session refresh token from login controller " + request.getSession().getAttribute("refreshToken"));


        */
        return new ResponseEntity<>(new AuthResponseDto(accessToken, refreshToken), HttpStatus.OK);
    }


    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto) {
        if (userRepository.existsByUsername(registerDto.getUsername())) {
            return new ResponseEntity<>("Username is taken!", HttpStatus.BAD_REQUEST);
        }

        Users user = new Users();
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode((registerDto.getPassword())));

        Roles roles = roleRepository.findByName("USER").get();
        user.setRoles(Collections.singletonList(roles));

        userRepository.save(user);

        return new ResponseEntity<>("User registered success!", HttpStatus.OK);
    }

    private String extractRefreshToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
    @PostMapping("/refreshToken")
    public ResponseEntity<AuthResponseDto> refreshToken(HttpServletRequest request, HttpServletResponse response, @RequestBody RefreshTokenDto refreshTokenDto) throws IOException {
        String refreshToken = extractRefreshToken(request);
        if (refreshToken != null && jwtGenerator.validateToken(refreshToken)) {

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            refreshTokenDto.getUsername(),
                            refreshTokenDto.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String newAccessToken = jwtGenerator.generateAccessToken(authentication);
            String newRefreshToken = jwtGenerator.generateAccessToken(authentication);

            return new ResponseEntity<>(new AuthResponseDto(newAccessToken, newRefreshToken), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);

    }



}

