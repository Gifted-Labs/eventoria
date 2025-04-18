package com.giftedlabs.eventoria.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
public class JwtService {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwt.ExpirationMs}")
    private String jwtExpiration;

    @Value("${app.jwt.RefreshExpirationMs}")
    private String jwtRefreshExpiration;



}
