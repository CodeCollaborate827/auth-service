package com.chat.auth_service.repository;

import com.chat.auth_service.entity.ApplicationToken;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface ApplicationTokenRepository extends R2dbcRepository<ApplicationToken, UUID> {
  Mono<ApplicationToken> findByToken(String refreshToken);
}
