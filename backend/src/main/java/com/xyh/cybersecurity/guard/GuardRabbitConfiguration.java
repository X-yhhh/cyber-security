package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.rabbitmq.client.Channel;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.connection.*;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** guard 专用 durable 队列；确认延迟重投成功后才 ack，最终失败进入可检查的死信队列。 */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(name="cyber.ingest.consumer.enabled",havingValue="true")
public class GuardRabbitConfiguration {
    @Bean Declarables guardQueues(@Value("${cyber.ingest.rabbitmq.exchange}") String exchange,
                                  @Value("${cyber.guard.queue-prefix:q.guard.v5}") String prefix){
        List<Declarable> all=new ArrayList<>();var ex=new TopicExchange(exchange,true,false);var retry=new DirectExchange(prefix+".retry",true,false);var dead=new DirectExchange(prefix+".dead",true,false);all.add(retry);all.add(dead);
        Queue q=QueueBuilder.durable(prefix).withArgument("x-dead-letter-exchange",dead.getName()).withArgument("x-dead-letter-routing-key","dead").build();all.add(q);all.add(BindingBuilder.bind(q).to(ex).with("guard.#"));
        Queue dl=QueueBuilder.durable(prefix+".dead").build();all.add(dl);all.add(BindingBuilder.bind(dl).to(dead).with("dead"));
        for(int i=1;i<=5;i++){Queue r=QueueBuilder.durable(prefix+".retry."+i).withArgument("x-message-ttl",1000*(1<<(i-1))).withArgument("x-dead-letter-exchange",exchange).withArgument("x-dead-letter-routing-key","guard.retry").build();all.add(r);all.add(BindingBuilder.bind(r).to(retry).with(Integer.toString(i)));}
        return new Declarables(all);
    }
    @Bean GuardListener guardListener(GuardDetection detection,RabbitTemplate ingestRabbitTemplate,@Value("${cyber.guard.queue-prefix:q.guard.v5}") String prefix){return new GuardListener(detection,ingestRabbitTemplate,prefix);}
    public static final class GuardListener {
        private final GuardDetection detection;private final RabbitTemplate rabbit;private final String prefix;
        public GuardListener(GuardDetection detection,RabbitTemplate rabbit,String prefix){this.detection=detection;this.rabbit=rabbit;this.prefix=prefix;}
        @RabbitListener(id="guardV5Consumer",queues="${cyber.guard.queue-prefix:q.guard.v5}",containerFactory="ingestRabbitListenerContainerFactory")
        public void receive(Message message,Channel channel)throws Exception{
            long tag=message.getMessageProperties().getDeliveryTag();JsonNode envelope;
            try{require(message.getBody().length<=1024*1024,"PAYLOAD_TOO_LARGE");envelope=parse(new String(message.getBody(),java.nio.charset.StandardCharsets.UTF_8));fields(envelope,"schemaVersion eventKey eventType payload","");uuid(envelope,"eventKey");require(envelope.path("schemaVersion").asInt()==1&&Set.of("guard.observation.accepted","guard.action.requested","guard.action.revoked","guard.action.observed","guard.decision.recorded").contains(text(envelope,"eventType")),"INVALID_EVENT");}
            catch(RuntimeException invalid){channel.basicReject(tag,false);return;}
            try{detection.consume(text(envelope,"eventKey"),text(envelope,"eventType"),envelope.get("payload"));channel.basicAck(tag,false);}
            catch(Exception failure){int attempt=((Number)message.getMessageProperties().getHeaders().getOrDefault("x-guard-attempt",0)).intValue()+1;
                if(attempt>5||failure instanceof com.xyh.cybersecurity.common.api.ApiRequestException){channel.basicReject(tag,false);return;}
                MessageProperties p=new MessageProperties();p.setContentType("application/json");p.setDeliveryMode(MessageDeliveryMode.PERSISTENT);p.setMessageId(text(envelope,"eventKey"));p.getHeaders().putAll(message.getMessageProperties().getHeaders());p.setHeader("x-guard-attempt",attempt);
                // 每个重试 routing key 返回原 guard 主题，保持队列隔离。
                p.setHeader("x-guard-original-topic",text(envelope,"eventType"));
                try{var confirm=new CorrelationData(id());rabbit.send(prefix+".retry",Integer.toString(attempt),new Message(message.getBody(),p),confirm);var ack=confirm.getFuture().get(5,TimeUnit.SECONDS);if(!ack.isAck()||confirm.getReturned()!=null)throw new IllegalStateException();channel.basicAck(tag,false);}
                catch(Exception unavailable){channel.basicNack(tag,false,true);}
            }
        }
    }
}
