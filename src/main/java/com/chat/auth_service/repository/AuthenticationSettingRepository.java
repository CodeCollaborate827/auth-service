package com.chat.auth_service.repository;

import com.chat.auth_service.entity.AuthenticationSetting;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthenticationSettingRepository extends R2dbcRepository<AuthenticationSetting, Long> {
    Mono<AuthenticationSetting> findByUserId(String userId);
}
