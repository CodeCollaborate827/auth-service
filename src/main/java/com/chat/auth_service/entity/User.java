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
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
public class User {
  @Id private UUID id;

  private String username;

  private String email;

  private String passwordHash;

  private AccountType accountType;

  private AccountStatus accountStatus;

  @CreatedDate private OffsetDateTime createdAt;

  @LastModifiedDate private OffsetDateTime updatedAt;

  public enum AccountType {
    NORMAL,
    GOOGLE
  }

  public enum AccountStatus {
    ACTIVE,
    INACTIVE,
    UNVERIFIED
  }
}
