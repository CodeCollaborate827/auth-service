package com.chat.auth_service.repository;

import com.chat.auth_service.entity.LoginHistory;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

@Repository
public interface LoginHistoryRepository extends R2dbcRepository<LoginHistory, UUID> {
  Flux<LoginHistory> findAllByUserId(UUID userId);
}
