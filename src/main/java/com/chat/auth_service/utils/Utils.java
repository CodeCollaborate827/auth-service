package com.chat.auth_service.utils;

import java.util.UUID;

public class Utils {

  public static UUID convertStringToUUID(String id) {
    return UUID.fromString(id);
  }

  public static String convertUUIDToString(UUID uuid) {
    return uuid.toString();
  }
}
