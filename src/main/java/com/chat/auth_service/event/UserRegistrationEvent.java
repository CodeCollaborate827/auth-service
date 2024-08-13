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
public class UserRegistrationEvent {
  private String userId;
  private String username;
  private String displayName;
  private String email;
  private OffsetDateTime createdAt;
  private String city;
  private String dateOfBirth;
  private Gender gender;
  private String avatar;

  public enum Gender {
    male,
    female,
    other
  }
}
