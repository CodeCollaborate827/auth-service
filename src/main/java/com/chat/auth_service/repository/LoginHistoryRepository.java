package com.chat.auth_service.repository;

import com.chat.auth_service.entity.LoginHistory;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface LoginHistoryRepository extends R2dbcRepository<LoginHistory, UUID> {
  @Query(
      "SELECT * FROM login_history WHERE user_id = :id "
          + "AND (ip_address = :ipAddress OR :ipAddress IS NULL) "
          + "AND (user_agent = :userAgent OR :userAgent IS NULL)")
  Mono<LoginHistory> findByUserIdAndIpAddressAndUserAgent(
      UUID id, String ipAddress, String userAgent);
}
