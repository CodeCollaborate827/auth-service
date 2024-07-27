package com.chat.auth_service.service.implementation;

import com.chat.auth_service.config.KafkaProducerConfig;
import com.chat.auth_service.event.NewRegistryEvent;
import com.chat.auth_service.service.KafkaProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Sinks;

@Slf4j
@Service
@RequiredArgsConstructor
public class KafkaProducerImpl implements KafkaProducer {

  @Override
  public void sendNewRegistryEvent(NewRegistryEvent event) {
    Message<NewRegistryEvent> message = MessageBuilder.withPayload(event).build();
    Sinks.EmitResult result = KafkaProducerConfig.newRegistrySink.tryEmitNext(message);
    if (result.isFailure()) {
      log.error("Failed to emit new registry event: {}", result);
    } else {
      log.info("New registry event emitted successfully");
    }
  }
}
