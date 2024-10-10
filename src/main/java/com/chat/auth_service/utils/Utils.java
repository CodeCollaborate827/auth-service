package com.chat.auth_service.utils;

import com.chat.auth_service.server.model.*;
import java.util.UUID;
import org.springframework.http.ResponseEntity;

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

  public static ResponseEntity<CommonResponse> createCommonSuccessResponse(
      String message, String requestId) {
    CommonResponse commonResponse = new CommonResponse();
    commonResponse.setRequestId(generateRequestId());
    commonResponse.setMessage(message);
    commonResponse.setRequestId(requestId);
    return ResponseEntity.ok(commonResponse);
  }

  public static CheckEmailExists200Response mapCheckEmailExistsResponse(String requestId) {
    return new CheckEmailExists200Response()
        .requestId(requestId)
        .data(new CheckEmailExists200ResponseAllOfData().isExists(false));
  }

  public static CheckUsernameExists200Response mapCheckUsernameExistsResponse(String requestId) {
    return new CheckUsernameExists200Response()
        .requestId(requestId)
        .data(new CheckUsernameExists200ResponseAllOfData().isExists(false));
  }
}
