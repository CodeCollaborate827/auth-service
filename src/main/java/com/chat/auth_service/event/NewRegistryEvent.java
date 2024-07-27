package com.chat.auth_service.event;

import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NewRegistryEvent {
  private String userId;
  private Registry registry;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class Registry {
    private String id;
    private String username;
    private String email;
    private OffsetDateTime createdAt;
  }
}
