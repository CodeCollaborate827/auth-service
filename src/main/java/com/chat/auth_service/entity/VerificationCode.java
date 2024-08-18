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
@Table(name = "verification_code")
@NoArgsConstructor
@AllArgsConstructor
public class VerificationCode {
  @Id private UUID id;

  @Column("user_email")
  private String userEmail;

  private OffsetDateTime expiration;
  private Type type;
  private String code;

  @CreatedDate
  @Column("created_at")
  private OffsetDateTime createdAt;

  @LastModifiedDate
  @Column("updated_at")
  private OffsetDateTime updatedAt;

  // changing the Type enum requires the changes in ErrorCode.AUTH_ERROR9
  public enum Type {
    ACCOUNT_REGISTRATION,
    FORGOT_PASSWORD
  }
}
