package com.chat.auth_service.utils;

import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.server.model.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.http.codec.multipart.FormFieldPart;
import org.springframework.http.codec.multipart.Part;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class Utils {
  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("MM/dd/yyyy");

  private Utils() {}

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

  public static Mono<String> extractValue(Flux<Part> partFlux) {
    return partFlux
        .next()
        .cast(FormFieldPart.class)
        .map(FormFieldPart::value)
        .doOnNext(value -> log.info("Value: {}", value))
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR21)));
  }

  public static Mono<FilePart> extractFile(Flux<Part> partFlux) {
    return partFlux
        .next()
        .cast(FilePart.class)
        .doOnNext(filePart -> log.info("File Name: {}", filePart.filename()))
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR21)));
  }

  public static Mono<LocalDate> extractDateValue(Flux<Part> partFlux) {
    return extractValue(partFlux).map(dateString -> LocalDate.parse(dateString, DATE_FORMATTER));
  }
}
