package com.chat.auth_service.repository;

import com.chat.auth_service.entity.LoginHistory;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

@Repository
public interface LoginHistoryRepository extends R2dbcRepository<LoginHistory, Long> {
    Flux<LoginHistory> findAllByUserId(String userId);
}
