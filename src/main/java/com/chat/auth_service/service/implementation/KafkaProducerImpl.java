package com.chat.auth_service.service.implementation;

import com.chat.auth_service.config.KafkaProducerConfig;
import com.chat.auth_service.event.Event;
import com.chat.auth_service.event.UserRegistrationEvent;
import com.chat.auth_service.service.KafkaProducer;
import com.chat.auth_service.utils.EventUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
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
  public void sendNewRegistryEvent(UserRegistrationEvent userRegistrationEvent) {
    Event event = null;
    try {
      event = EventUtils.buildEvent(userRegistrationEvent);
      Message<Event> message = MessageBuilder.withPayload(event).build();
      Sinks.EmitResult result =
          KafkaProducerConfig.userRegistrationDownstreamSink.tryEmitNext(message);
      if (result.isFailure()) {
        log.error("Failed to emit new registry event: {}", result);
      } else {
        log.info("New registry event emitted successfully");
      }
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }
}
