package com.xyh.cybersecurity.ingest.outbox;

import org.springframework.amqp.core.AcknowledgeMode;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.boot.autoconfigure.amqp.SimpleRabbitListenerContainerFactoryConfigurer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.core.Declarable;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * M2 消费拓扑。只有显式打开 outbox relay/consumer 时才连接并声明队列，避免开发环境意外接入 RabbitMQ。
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "cyber.ingest.consumer.enabled", havingValue = "true")
public class RabbitTopologyConfig {
    public static final String INGEST_ROUTE = "ingest.batch.received";

    @Bean
    TopicExchange ingestDeadLetterExchange(
            @Value("${cyber.ingest.rabbitmq.dead-letter-exchange:cyber-security.dlx}") String name) {
        return new TopicExchange(name, true, false);
    }

    @Bean
    Queue ingestBatchReceivedQueue(
            @Value("${cyber.ingest.consumer.queue:q.ingest.batch.received}") String name,
            @Value("${cyber.ingest.rabbitmq.dead-letter-exchange:cyber-security.dlx}") String deadLetterExchange) {
        return QueueBuilder.durable(name)
                .withArgument("x-dead-letter-exchange", deadLetterExchange)
                .build();
    }

    @Bean
    Binding ingestBatchReceivedBinding(Queue ingestBatchReceivedQueue,
                                      @Qualifier("ingestEventsExchange") TopicExchange ingestEventsExchange) {
        return BindingBuilder.bind(ingestBatchReceivedQueue).to(ingestEventsExchange).with(INGEST_ROUTE);
    }

    @Bean
    Queue ingestDeadLetterQueue(
            @Value("${cyber.ingest.consumer.dead-letter-queue:q.ingest.dead}") String name) {
        return QueueBuilder.durable(name).build();
    }

    @Bean
    Binding ingestDeadLetterBinding(Queue ingestDeadLetterQueue,
                                   @Qualifier("ingestDeadLetterExchange") TopicExchange ingestDeadLetterExchange) {
        return BindingBuilder.bind(ingestDeadLetterQueue).to(ingestDeadLetterExchange).with(INGEST_ROUTE);
    }

    /** 为 1..5 次失败声明固定 TTL 队列；TTL 到期后回到主 topic，消费者仍以数据库台账计数。 */
    @Bean
    Declarables ingestRetryDeclarables(
            @Qualifier("ingestDeadLetterExchange") TopicExchange ingestDeadLetterExchange,
            @Value("${cyber.ingest.consumer.retry-queue-prefix:q.ingest.batch.received.retry.}") String prefix,
            @Value("${cyber.ingest.rabbitmq.dead-letter-exchange:cyber-security.dlx}") String deadLetterExchange,
            @Value("${cyber.ingest.rabbitmq.exchange:cyber-security.ingest.events}") String ingestExchange) {
        List<Declarable> declarations = new ArrayList<>();
        for (int attempt = 1; attempt <= IngestBatchConsumer.MAX_RETRIES; attempt++) {
            long ttl = Math.min(3_600_000L, 1_000L << Math.min(attempt - 1, 11));
            Queue queue = QueueBuilder.durable(prefix + attempt)
                    .withArgument("x-message-ttl", ttl)
                    .withArgument("x-dead-letter-exchange", ingestExchange)
                    .withArgument("x-dead-letter-routing-key", INGEST_ROUTE)
                    .build();
            declarations.add(queue);
            declarations.add(BindingBuilder.bind(queue).to(ingestDeadLetterExchange)
                    .with(INGEST_ROUTE + ".retry." + attempt));
        }
        return new Declarables(declarations);
    }

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

    @Bean
    IngestRetryPublisher ingestRetryPublisher(RabbitTemplate ingestRabbitTemplate,
                                              @Value("${cyber.ingest.rabbitmq.dead-letter-exchange:cyber-security.dlx}") String deadLetterExchange,
                                              @Value("${cyber.ingest.rabbitmq.confirm-timeout-ms:5000}") long confirmTimeoutMs) {
        return new IngestRetryPublisher(ingestRabbitTemplate, deadLetterExchange, confirmTimeoutMs);
    }

    /** 使用 publisher confirm 后才允许监听器确认原消息，避免延迟队列转发失败时丢失事件。 */
    static final class IngestRetryPublisher {
        private final RabbitTemplate template;
        private final String deadLetterExchange;
        private final long confirmTimeoutMs;

        IngestRetryPublisher(RabbitTemplate template, String deadLetterExchange, long confirmTimeoutMs) {
            this.template = template;
            this.deadLetterExchange = deadLetterExchange;
            this.confirmTimeoutMs = confirmTimeoutMs;
        }

        void publish(Message original, int retryAttempt) throws Exception {
            MessageProperties properties = new MessageProperties();
            properties.setContentType(original.getMessageProperties().getContentType());
            properties.setContentEncoding(original.getMessageProperties().getContentEncoding());
            properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
            properties.setMessageId(original.getMessageProperties().getMessageId());
            properties.setType(original.getMessageProperties().getType());
            properties.getHeaders().putAll(original.getMessageProperties().getHeaders());
            properties.setHeader("x-ingest-retry-attempt", retryAttempt);
            Message retry = new Message(original.getBody(), properties);
            String route = INGEST_ROUTE + ".retry." + retryAttempt;
            CorrelationData correlation = new CorrelationData(properties.getMessageId());
            template.send(deadLetterExchange, route, retry, correlation);
            var confirm = correlation.getFuture().get(confirmTimeoutMs, TimeUnit.MILLISECONDS);
            if (!confirm.isAck() || correlation.getReturned() != null) {
                throw new IllegalStateException("INGEST_RETRY_PUBLISH_REJECTED");
            }
        }
    }
}
