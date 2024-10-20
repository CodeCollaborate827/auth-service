package com.chat.auth_service.service;

import org.springframework.http.codec.multipart.FilePart;
import reactor.core.publisher.Mono;

public interface MediaService {
  Mono<Object> uploadImage(String operation, String requestId, Mono<FilePart> filePartMono);
}
