package com.chat.auth_service.repository;

import com.chat.auth_service.entity.RefreshToken;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends R2dbcRepository<RefreshToken, UUID> {}
