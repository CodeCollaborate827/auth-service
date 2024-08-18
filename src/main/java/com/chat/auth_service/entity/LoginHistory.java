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
@Table(name = "login_history")
@NoArgsConstructor
@AllArgsConstructor
public class LoginHistory {
  @Id private UUID id;

  @Column("user_id")
  private UUID userId;

  @Column("ip_address")
  private String ipAddress;

  @Column("user_agent")
  private String userAgent;

  @Column("is_successful")
  private Boolean isSuccessful;

  //  private Boolean isSaved;
  @CreatedDate
  @Column("created_at")
  private OffsetDateTime createdAt;

  @LastModifiedDate
  @Column("updated_at")
  private OffsetDateTime updatedAt;
}
