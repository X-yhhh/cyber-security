package com.xyh.cybersecurity.ingest.outbox;

import org.springframework.amqp.core.AcknowledgeMode;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.amqp.SimpleRabbitListenerContainerFactoryConfigurer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 消费端容器工厂。只有显式打开 consumer 时才创建，避免开发环境意外接入 RabbitMQ；
 * guard 的队列、重试与死信拓扑由 {@code GuardRabbitConfiguration} 自行声明。
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "cyber.ingest.consumer.enabled", havingValue = "true")
public class RabbitTopologyConfig {

    /** 手动确认、拒绝不重排：监听器在业务事务成功后才 ack，失败交由各自的重试/死信队列。 */
    @Bean
    SimpleRabbitListenerContainerFactory ingestRabbitListenerContainerFactory(
            SimpleRabbitListenerContainerFactoryConfigurer configurer,
            CachingConnectionFactory ingestRabbitConnectionFactory,
            @Value("${cyber.ingest.consumer.prefetch:10}") int prefetch) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        configurer.configure(factory, ingestRabbitConnectionFactory);
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        factory.setPrefetchCount(prefetch);
        factory.setDefaultRequeueRejected(false);
        return factory;
    }
}
