package com.chat.auth_service.entity;

import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Data
@Table(name = "authentication_settings")
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationSetting {
  @Id private UUID id;
  private UUID userId;

  @Column("mfa_enabled")
  private Boolean mfaEnabled;

  @Column("newLoginNotification")
  private Boolean newLoginNotification;

  @Column("mfaType")
  private MfaType mfaType;

  @CreatedDate
  @Column("created_at")
  private OffsetDateTime createdAt;

  @LastModifiedDate
  @Column("updated_at")
  private OffsetDateTime updatedAt;

  public enum MfaType {
    VERIFY_EMAIL_CODE,
    GOOGLE_AUTHENTICATOR
  }
}
