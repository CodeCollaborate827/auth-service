package com.chat.auth_service.repository;

import com.chat.auth_service.entity.VerificationCode;
import java.util.UUID;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface VerificationCodeRepository extends R2dbcRepository<VerificationCode, UUID> {

  @Query("SELECT * FROM verification_code WHERE user_id = :userId AND type = :type ORDER BY created_at DESC LIMIT 1")
  Mono<VerificationCode> findByUserIdAndTypeLatest(UUID userId, VerificationCode.Type type);
}
