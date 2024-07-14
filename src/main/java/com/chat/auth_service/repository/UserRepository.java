package com.chat.auth_service.repository;

import com.chat.auth_service.entity.User;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UserRepository extends R2dbcRepository<User, UUID> {
  Mono<User> findByEmail(String email);

  Mono<User> findByUsername(String username);
}
