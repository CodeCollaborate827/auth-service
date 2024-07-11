package com.chat.auth_service.repository;

import com.chat.auth_service.entity.VerificationCode;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VerificationCodeRepository extends R2dbcRepository<VerificationCode, Long> {
}
