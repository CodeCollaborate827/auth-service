package com.chat.auth_service.utils;

import com.chat.auth_service.event.NewRegistryEvent;
import java.util.Map;
import java.util.UUID;
import org.springframework.kafka.support.serializer.JsonSerializer;

public class Utils {
  public static UUID convertStringToUUID(String id) {
    return UUID.fromString(id);
  }

  public static String convertUUIDToString(UUID uuid) {
    return uuid.toString();
  }

  public static Map<String, Object> addTypeMapping(Map<String, Object> props) {
    Class[] subscribedEventClasses = {NewRegistryEvent.class};

    String typeMapping = "";
    for (Class eventClass : subscribedEventClasses) {
      String simpleName = eventClass.getSimpleName();
      String name = eventClass.getName();
      typeMapping += simpleName + ":" + name + ",";
    }

    // remove the last comma
    typeMapping = typeMapping.substring(0, typeMapping.length() - 1);

    // after the loop the typeMapping will be like this:
    // NewConversationEvent:com.imatalk.wshandlerservice.events.NewConversationEvent,
    // NewFriendRequestEvent:com.imatalk.wshandlerservice.events.NewFriendRequestEvent,...

    props.put(JsonSerializer.TYPE_MAPPINGS, typeMapping);

    return props;
  }
}
