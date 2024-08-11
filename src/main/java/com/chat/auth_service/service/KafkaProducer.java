package com.chat.auth_service.service;

import com.chat.auth_service.event.UserRegistrationEvent;

public interface KafkaProducer {
  void sendNewRegistryEvent(UserRegistrationEvent data);
}
