package com.chat.auth_service.service;

import com.chat.auth_service.event.NewRegistryEvent;

public interface KafkaProducer {
  void sendNewRegistryEvent(NewRegistryEvent data);
}
