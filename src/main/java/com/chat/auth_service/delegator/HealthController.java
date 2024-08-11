package com.chat.auth_service.delegator;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/")
public class HealthController {

  @Value("${spring.application.name}")
  private String applicationName;

  @GetMapping("/health")
  public Map<String, Object> getHealth() {
    Map<String, Object> map = new HashMap<String, Object>();
    map.put("name", applicationName);
    map.put("timestamp", OffsetDateTime.now());
    return map;
  }
}
