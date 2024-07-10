package com.chat.auth_service.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Data
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    private String id;

    private Integer username;

    private String email;

    private Integer passwordHash;

    private String accountType;

    private String accountStatus;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}
