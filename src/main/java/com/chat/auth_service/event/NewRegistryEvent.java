package com.chat.auth_service.event;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NewRegistryEvent {
    private String userId;
    private Registry registry;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Registry {
        private String id;
        private String username;
        private String email;
        private OffsetDateTime createdAt;
    }
}
