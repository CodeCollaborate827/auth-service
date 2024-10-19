package com.chat.auth_service.service.implementation;

import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.response.CommonResponse;
import com.chat.auth_service.service.MediaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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

  @Value("${media-service.url}")
  private String MEDIA_SERVICE_URL;

  @Override
  public Mono<Object> uploadImage(String operation, String requestId, Mono<FilePart> filePartMono) {
    return filePartMono
        .flatMap(this::uploadToCloudStorage)
        .onErrorResume(error -> Mono.error(new ApplicationException(ErrorCode.MEDIA_UPLOAD_FAILED)))
        .mapNotNull(ResponseEntity::getBody)
        .map(CommonResponse::getData);
  }

  private Mono<ResponseEntity<CommonResponse>> uploadToCloudStorage(FilePart filePart) {
    return webClientBuilder
        .build()
        .post()
        .uri(MEDIA_SERVICE_URL)
        .contentType(MediaType.MULTIPART_FORM_DATA)
        .body(BodyInserters.fromMultipartData("image", filePart))
        .retrieve()
        .toEntity(CommonResponse.class);
  }
}
