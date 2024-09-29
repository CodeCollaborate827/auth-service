package com.chat.auth_service.utils;

import com.chat.auth_service.server.model.CommonResponse;
import org.springframework.http.ResponseEntity;

import java.util.UUID;

public class Utils {
  public static UUID convertStringToUUID(String id) {
    return UUID.fromString(id);
  }

  public static String convertUUIDToString(UUID uuid) {
    return uuid.toString();
  }

  public static String generateRequestId() {
    return UUID.randomUUID().toString();
  }

  public static ResponseEntity<CommonResponse> createCommonSuccessResponse(String message, String requestId) {
    CommonResponse commonResponse = new CommonResponse();
    commonResponse.setRequestId(generateRequestId());
    commonResponse.setMessage(message);
    commonResponse.setRequestId(requestId);
    return ResponseEntity.ok(commonResponse);
  }
}
