package com.chat.auth_service.event;

import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Event {

  @Builder.Default private String specVersion = "1.0";
  private String type;
  @Builder.Default private String id = UUID.randomUUID().toString();
  @Builder.Default private OffsetDateTime time = OffsetDateTime.now();
  @Builder.Default private String dataContentType = "application/json";
  private String payloadBase64;
}
