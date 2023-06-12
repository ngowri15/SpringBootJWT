package com.alphanove.springboot_security.security;

import java.time.Duration;

public class SecurityConstants {

    public static final String JWT_SECRET = "secret";
    public static final long JWT_EXPIRATION = 60000;
    public static final long JWT_REFRESH_EXPIRATION =300000;
    public static final Duration JWT_REFRESH_THRESHOLD = Duration.ofMillis(20000);


}
