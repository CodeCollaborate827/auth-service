package com.chat.auth_service.service.implementation;

import com.chat.auth_service.config.KafkaProducerConfig;
import com.chat.auth_service.event.NewRegistryEvent;
import com.chat.auth_service.service.KafkaProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class KafkaProducerImpl implements KafkaProducer {
  private final KafkaProducerConfig kafkaProducerConfig;

  @Override
  public <T> Mono<Void> send(String bindingDestination, T data) {
    log.info("Sending data to Kafka topic: {}, data: {}", bindingDestination, data);
    return Mono.fromRunnable(
        () -> kafkaProducerConfig.sendNewRegistryEvent((NewRegistryEvent) data));
  }
}
