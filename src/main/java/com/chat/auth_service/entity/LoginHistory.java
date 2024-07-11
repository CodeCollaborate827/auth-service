package com.chat.auth_service.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Data
@Table(name = "login_history")
@NoArgsConstructor
@AllArgsConstructor
public class LoginHistory {
    @Id
    private Long id;
    private String userId;
    private String ipAddress;
    private String userAgent;
    private Boolean isSuccessful;
    private Boolean isSaved;
    @CreatedDate
    private LocalDateTime createdAt;
    @LastModifiedDate
    private LocalDateTime updatedAt;
}
