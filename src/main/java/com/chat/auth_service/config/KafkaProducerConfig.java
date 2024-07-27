package com.chat.auth_service.config;

import com.chat.auth_service.event.NewRegistryEvent;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

@Slf4j
@Configuration
public class KafkaProducerConfig {
  private final Sinks.Many<Message<NewRegistryEvent>> newRegistrySink =
      Sinks.many().unicast().onBackpressureBuffer();

  @Bean
  public Supplier<Flux<Message<NewRegistryEvent>>> sendNewRegistry() {
    return newRegistrySink::asFlux;
  }

  public void sendNewRegistryEvent(NewRegistryEvent event) {
    Message<NewRegistryEvent> message = MessageBuilder.withPayload(event).build();
    Sinks.EmitResult result = newRegistrySink.tryEmitNext(message);
    if (result.isFailure()) {
      log.error("Failed to emit new registry event: {}", result);
    } else {
      log.info("New registry event emitted successfully");
    }
  }
}
