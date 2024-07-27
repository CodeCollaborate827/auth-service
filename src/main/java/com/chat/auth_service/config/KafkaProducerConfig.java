package com.chat.auth_service.config;

import jakarta.annotation.PostConstruct;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.support.serializer.JsonSerializer;
import reactor.kafka.sender.KafkaSender;
import reactor.kafka.sender.SenderOptions;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaProducerConfig {
    private SenderOptions<String,String> senderOptions;

    @Value("${topic.new-register}")
    private String NEW_REGISTER_TOPIC;

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.producer.compression-type}")
    private String compressionType;

    @Bean
    public NewTopic newRegistryTopic() {
        return TopicBuilder.name(NEW_REGISTER_TOPIC)
                .partitions(1)
                .replicas(1)
                .build();
    }

    @PostConstruct
    public void initProducer(KafkaProperties kafkaProperties, SslBundles sslBundles) {
        // using buildProducerProperties(SslBundles bundles) instead of buildProducerProperties() to avoid SSL issues
        Map<String, Object> producerProps = new HashMap<>(kafkaProperties.buildProducerProperties(sslBundles));
        producerProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        producerProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        producerProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);

        this.senderOptions = SenderOptions.create(producerProps);
    }

    @Bean
    public KafkaSender<?, ?> kafkaSender() {
        return KafkaSender.create(this.senderOptions);
    }
}
