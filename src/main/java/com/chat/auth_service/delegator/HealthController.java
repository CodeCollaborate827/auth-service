package com.chat.auth_service.delegator;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth/")
@Slf4j
public class HealthController {

  @Value("${spring.application.name}")
  private String applicationName;

  @GetMapping("/health")
  public Map<String, Object> getHealth() {
    log.info("Health check via GET");
    Map<String, Object> map = new HashMap<String, Object>();
    map.put("name", applicationName);
    map.put("timestamp", OffsetDateTime.now());
    return map;
  }


  @PostMapping("/health")
  public Map<String, Object> postHealth() {
    log.info("Health check via POST");
    Map<String, Object> map = new HashMap<String, Object>();
    map.put("name", applicationName);
    map.put("timestamp", OffsetDateTime.now());
    return map;
  }
}
