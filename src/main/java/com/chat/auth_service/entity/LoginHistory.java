package com.chat.auth_service.entity;

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
@Table(name = "login_history")
@NoArgsConstructor
@AllArgsConstructor
public class LoginHistory {
  @Id private UUID id;
  private UUID userId;
  private String ipAddress;
  private String userAgent;
  private Boolean isSuccessful;
  private Boolean isSaved;
  @CreatedDate private OffsetDateTime createdAt;
  @LastModifiedDate private OffsetDateTime updatedAt;
}
