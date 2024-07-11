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
@Table(name = "verification_code")
@NoArgsConstructor
@AllArgsConstructor
public class VerificationCode {
    @Id
    private Long id;
    private String userId;
    private LocalDateTime expiration;
    private Type type;
    private String code;
    @CreatedDate
    private LocalDateTime createdAt;
    @LastModifiedDate
    private LocalDateTime updatedAt;

    public enum Type {
        VERIFY_EMAIL,
        RESET_PASSWORD
    }
}
