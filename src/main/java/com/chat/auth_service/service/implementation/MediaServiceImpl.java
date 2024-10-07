package com.chat.auth_service.service.implementation;

import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.response.CommonResponse;
import com.chat.auth_service.service.MediaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class MediaServiceImpl implements MediaService {
  private final WebClient.Builder webClientBuilder;

  // TODO: move to application.yaml
  private static final String MEDIA_SERVICE_URL = "http://media-service/api/media/image";

  @Override
  public Mono<Void> uploadImage(String operation, String requestId, Mono<FilePart> filePartMono) {
    return filePartMono
        .flatMap(this::uploadToCloudStorage)
        .doOnSuccess(
            response -> {
              if (response.getStatusCode().is2xxSuccessful()) {
                log.info(
                    "Image uploaded successfully for operation: {}, requestId: {}",
                    operation,
                    requestId);
              } else {
                log.error(
                    "Failed to upload image for operation: {}, requestId: {}. Status: {}",
                    operation,
                    requestId,
                    response.getStatusCode());
              }
            })
        .onErrorResume(error -> Mono.error(new ApplicationException(ErrorCode.MEDIA_UPLOAD_FAILED)))
        .then();
  }

  private Mono<ResponseEntity<CommonResponse>> uploadToCloudStorage(FilePart filePart) {
    return webClientBuilder
        .build()
        .post()
        .uri(MEDIA_SERVICE_URL)
        .contentType(MediaType.MULTIPART_FORM_DATA)
        .body(BodyInserters.fromMultipartData("image", filePart))
        .retrieve()
        .toEntity(CommonResponse.class)
        .onErrorResume(
            error -> {
              log.error("Error uploading image to media-service", error);
              return Mono.just(
                  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                      .body(
                          CommonResponse.builder()
                              .errorCode(ErrorCode.MEDIA_UPLOAD_FAILED)
                              .build()));
            });
  }
}
