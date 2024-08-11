package com.chat.auth_service.utils;

import com.chat.auth_service.event.Event;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.Base64;

public class EventUtils {

  private static ObjectMapper objectMapper =
      JsonMapper.builder()
          // Register JavaTimeModule to handle Java 8 date/time types
          .addModule(new JavaTimeModule())
          .build();

  public static Event buildEvent(Object obj) throws JsonProcessingException {
    String json = objectMapper.writeValueAsString(obj);
    String encodedJson = encodeBase64(json);
    Event event =
        Event.builder().type(obj.getClass().toString()).payloadBase64(encodedJson).build();

    return event;
  }

  private static String encodeBase64(String json) {
    return Base64.getEncoder().encodeToString(json.getBytes());
  }
}
