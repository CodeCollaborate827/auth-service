package com.chat.auth_service.repository;

import com.chat.auth_service.entity.AuthenticationSetting;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthenticationSettingRepository
    extends R2dbcRepository<AuthenticationSetting, UUID> {
  Mono<AuthenticationSetting> findByUserId(UUID userId);
}
