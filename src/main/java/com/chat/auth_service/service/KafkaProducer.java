package com.chat.auth_service.service;

import reactor.core.publisher.Mono;

public interface KafkaProducer {
  <T> Mono<Void> send(String bindingDestination, T data);
}
