package com.chat.auth_service.service.implementation;

import com.chat.auth_service.event.NewRegistryEvent;
import com.chat.auth_service.service.EventProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.kafka.sender.KafkaSender;
import org.springframework.beans.factory.annotation.Value;

@Slf4j
@Service
@RequiredArgsConstructor
public class EventProducerImpl implements EventProducer {
    @Value("${topic.new-register}")
    private String NEW_REGISTER_TOPIC;

    private final KafkaSender<String, NewRegistryEvent> kafkaSender;

    @Override
    public void produceNewRegistryEvent(User user) {
        NewRegistryEvent.Registry registry = NewRegistryEvent.Registry.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .createdAt(user.getCreatedAt())
                .build();
        NewRegistryEvent newRegistryEvent = NewRegistryEvent.builder()
                .userId(user.getId())
                .registry(registry)
                .build();

        kafkaSender.createOutbound()
                .send(Mono.just(new ProducerRecord<>(NEW_REGISTER_TOPIC, newRegistryEvent)))
                .then()
                .doOnSuccess(s -> log.info("NewRegistryEvent sent successfully"))
                .subscribe();
    }
}
