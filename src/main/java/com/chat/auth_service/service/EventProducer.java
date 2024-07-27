package com.chat.auth_service.service;

import com.chat.auth_service.event.NewRegistryEvent;
import reactor.core.publisher.Mono;

public interface EventProducer {
    void produceNewRegistryEvent(User user);
}
