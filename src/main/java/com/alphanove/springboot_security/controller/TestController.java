package com.alphanove.springboot_security.controller;

import com.alphanove.springboot_security.dto.AuthResponseDto;
import com.alphanove.springboot_security.dto.RefreshTokenDto;
import com.alphanove.springboot_security.security.JWTGenerator;
import com.alphanove.springboot_security.security.SecurityConstants;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@RestController
@RequestMapping("/api")
public class TestController {

    private JWTGenerator jwtGenerator;
    private final AuthenticationManager authenticationManager;


    public TestController(JWTGenerator jwtGenerator, AuthenticationManager authenticationManager) {
        this.jwtGenerator = jwtGenerator;
        this.authenticationManager = authenticationManager;
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }


    @GetMapping("/user")
    public ResponseEntity<String> user(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String token = extractTokenFromRequest(request);


        if (token != null && jwtGenerator.validateToken(token)) {

            response.sendRedirect("http://localhost:8080/api/check?token=" + token);

            String username = jwtGenerator.getUsernameFromJWT(token);
            // Other logic...
            return ResponseEntity.ok("Access granted to : " + username);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized access");
    }


    @GetMapping("/admin")
    public ResponseEntity<String> admin(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String accessToken = extractTokenFromRequest(request);

            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> responseEntity = restTemplate.getForEntity("http://localhost:8080/api/check?token=" + accessToken, String.class);

            if (responseEntity.getStatusCode() == HttpStatus.OK) {
                // Token validation was successful, allow access to the "/admin" endpoint
                return ResponseEntity.ok("Access granted to admin endpoint");
            }
            // Token validation failed, return an appropriate response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized access. Please login to get access.");

    }

    @GetMapping("/check")
    public ResponseEntity<Boolean> check(HttpServletRequest request, HttpServletResponse response, RefreshTokenDto refreshTokenDto) throws IOException {

        String token = extractTokenFromRequest(request);

        if (token != null && jwtGenerator.validateToken(token)) {
            return ResponseEntity.ok(true);
        }
        return ResponseEntity.ok(false);

        /*

        //String accessToken = (String) request.getSession().getAttribute("accessToken");
        //String refreshToken = (String) request.getSession().getAttribute("refreshToken");

        Instant expireTime = jwtGenerator.extractExpirationTimeFromToken(accessToken);
        Instant currentTime = Instant.now();
        Instant thresholdTime = currentTime.plus(SecurityConstants.JWT_REFRESH_THRESHOLD);
        if (expireTime.isBefore(thresholdTime)) {
            if (accessToken != null && jwtGenerator.validateToken(accessToken)) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        } else if (expireTime != null && jwtGenerator.validateToken(refreshToken)) {

            //String username = (String) request.getSession().getAttribute("username");
            //String password = (String) request.getSession().getAttribute("password");

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            refreshTokenDto.getUsername(),
                            refreshTokenDto.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String newAccessToken = jwtGenerator.generateAccessToken(authentication);
            String newRefreshToken = jwtGenerator.generateAccessToken(authentication);

            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);

        */


    }

    private String extractRefreshToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

}
