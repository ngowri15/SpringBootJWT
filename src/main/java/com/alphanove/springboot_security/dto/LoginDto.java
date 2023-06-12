package com.alphanove.springboot_security.dto;

import lombok.Data;

@Data
public class LoginDto {
    private String username;
    private String password;
}