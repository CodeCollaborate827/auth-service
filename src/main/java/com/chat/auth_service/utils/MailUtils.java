package com.chat.auth_service.utils;

import com.chat.auth_service.entity.VerificationCode;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class MailUtils {
  private final JavaMailSender mailSender;
  private final ResourceLoader resourceLoader;

  @Value("${mail.path.register-verification-mail}")
  private String verificationMailPath;

  @Value("${mail.from}")
  private String from;

  @Autowired
  private ResourceLoader resourceLoader;

  @Async("mailSenderThreadPoolTaskExecutor")
  public void sendVerificationEmail(String subject, String email, VerificationCode code) {
    // send mail
    MimeMessage message = mailSender.createMimeMessage();
    // read this: https://stackoverflow.com/questions/24798695/spring-async-method-inside-a-service
    try {
      message.setFrom(new InternetAddress(from));
      message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(email));
      message.setSubject(subject);

      String htmlTemplate = readFile(verificationMailPath);
      //      htmlTemplate = htmlTemplate.replace("${name}", user.getUsername());
      htmlTemplate = htmlTemplate.replace("${verificationCode}", code.getCode());
      message.setContent(htmlTemplate, "text/html; charset=utf-8");
      log.info("Sending email ...");
      mailSender.send(message);
      log.info("Sent email successfull!");
    } catch (Exception e) {
      log.error("ERROR when sending the email: {}", e);
    }
  }

  private String readFile(String verificationMailPath) throws IOException {
    Resource resource = resourceLoader.getResource(verificationMailPath);
    return Files.readString(Path.of(resource.getURI()), StandardCharsets.UTF_8);
  }
}
