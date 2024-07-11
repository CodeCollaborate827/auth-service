package com.chat.auth_service.repository;

import com.chat.auth_service.entity.RefreshToken;
import org.springframework.data.r2dbc.repository.R2dbcRepository;

public interface RefreshTokenRepository extends R2dbcRepository<RefreshToken, Long> {
}
