package com.alphanove.springboot_security.dto;

import lombok.Data;

@Data
public class RefreshTokenDto {
    private String username;
    private String password;
}
