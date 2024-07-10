package com.chat.auth_service.service.implementation;

import com.chat.auth_service.repository.UserRepository;
import com.chat.auth_service.server.model.Login200Response;
import com.chat.auth_service.server.model.LoginRequest;
import com.chat.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final static Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;

    @Override
    public Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest) {
        return null;
    }
}
