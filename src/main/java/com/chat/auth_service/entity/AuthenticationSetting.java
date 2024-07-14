package com.chat.auth_service.entity;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Table;

@Data
@Table(name = "authentication_setting")
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationSetting {
  @Id private UUID id;
  private UUID userId;
  private Boolean mfaEnabled;
  private Boolean newLoginNotification;
  private MfaType mfaType;
  @CreatedDate private OffsetDateTime createdAt;
  @LastModifiedDate private OffsetDateTime updatedAt;

  public enum MfaType {
    VERIFY_EMAIL_CODE,
    GOOGLE_AUTHENTICATOR
  }
}
