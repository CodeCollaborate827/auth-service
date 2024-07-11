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
@Table(name = "authentication_setting")
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationSetting {
    @Id
    private Long id;
    private String userId;
    private Boolean mfaEnabled;
    private Boolean newLoginNotification;
    private MfaType mfaType;
    @CreatedDate
    private LocalDateTime createdAt;
    @LastModifiedDate
    private LocalDateTime updatedAt;

    public enum MfaType {
        VERIFY_EMAIL_CODE,
        GOOGLE_AUTHENTICATOR
    }
}
