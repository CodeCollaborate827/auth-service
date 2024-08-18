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
@Table(name = "application_tokens")
@NoArgsConstructor
@AllArgsConstructor
public class ApplicationToken {
  @Id private UUID id;
  private String token;

  @Column("token_type")
  private TokenType tokenType;

  @Column("usage_count")
  private Integer usageCount;

  @Column("limit_usage_count")
  private Integer limitUsageCount;

  @Column("last_used")
  private OffsetDateTime lastUsed;

  @CreatedDate
  @Column("created_at")
  private OffsetDateTime createdAt;

  @LastModifiedDate
  @Column("updated_at")
  private OffsetDateTime updatedAt;

  public enum TokenType {
    REFRESH_TOKEN,
    RESET_PASSWORD_TOKEN
  }
}
