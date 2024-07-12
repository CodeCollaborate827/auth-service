package com.chat.auth_service.utils;

import com.chat.auth_service.entity.User;
import com.chat.auth_service.entity.VerificationCode;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;

@Component
@RequiredArgsConstructor
public class MailUtils {
    private final JavaMailSender mailSender;

    @Value("${mail.path.register-verification-mail}")
    private String verificationMailPath;

    @Value("${mail.from}")
    private String from;

    @Async
    public CompletableFuture<Mono<Void>> sendVerificationEmail(String subject, User user, VerificationCode code) {
        // send mail
        MimeMessage message = mailSender.createMimeMessage();

        try {
            message.setFrom(new InternetAddress(from));
            message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(user.getEmail()));
            message.setSubject(subject);

            String htmlTemplate = readFile(verificationMailPath);
            htmlTemplate = htmlTemplate.replace("${name}", user.getUsername());
            htmlTemplate = htmlTemplate.replace("${verificationCode}", code.getCode());

            message.setContent(htmlTemplate, "text/html; charset=utf-8");
            return CompletableFuture.completedFuture(Mono.fromRunnable(() -> mailSender.send(message)));
        } catch (MessagingException | IOException e) {
            return CompletableFuture.completedFuture(Mono.error(e));
        }
    }

    private String readFile(String verificationMailPath) throws IOException {
        Path path = Paths.get(verificationMailPath);
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
