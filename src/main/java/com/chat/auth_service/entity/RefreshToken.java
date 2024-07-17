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
@Table(name = "refresh_token")
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
  @Id private UUID id;
  private UUID loginId;
  private String refreshToken;
  private Integer usageCount;
  private Integer limitUsageCount;
  private OffsetDateTime lastUsed;
  @CreatedDate private OffsetDateTime createdAt;
  @LastModifiedDate private OffsetDateTime updatedAt;
}
