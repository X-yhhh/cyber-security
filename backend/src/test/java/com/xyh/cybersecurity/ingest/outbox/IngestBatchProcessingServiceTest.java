package com.xyh.cybersecurity.ingest.outbox;

import com.xyh.cybersecurity.ingest.IngestMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IngestBatchProcessingServiceTest {
    @Test
    void duplicateConsumedMessageDoesNotSubmitAgain() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<InferenceTaskSubmitter> provider = mock(ObjectProvider.class);
        when(mapper.findConsumedMessageForUpdate(IngestBatchProcessingService.CONSUMER_NAME, "event-1"))
                .thenReturn(new IngestMapper.ConsumedMessageRow(1, IngestBatchProcessingService.CONSUMER_NAME,
                        "event-1", "consumed", 0, null, null, Instant.now()));

        IngestBatchProcessingService service = new IngestBatchProcessingService(mapper, provider);

        assertThat(service.process(new IngestBatchEvent("event-1", RabbitTopologyConfig.INGEST_ROUTE, 7, 3, 0)))
                .isEqualTo(IngestBatchProcessingService.ProcessResult.DUPLICATE);
        verify(provider, org.mockito.Mockito.never()).getIfAvailable();
    }

    @Test
    void onlyAcceptedRecordsAreSubmittedAndMarkedConsumed() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<InferenceTaskSubmitter> provider = mock(ObjectProvider.class);
        InferenceTaskSubmitter submitter = mock(InferenceTaskSubmitter.class);
        when(provider.getIfAvailable()).thenReturn(submitter);
        IngestMapper.AcceptedRecord record = new IngestMapper.AcceptedRecord(9, 7, 3, "record-1", Instant.now(), 4, "{}");
        when(mapper.findAcceptedRecords(7)).thenReturn(List.of(record));
        IngestBatchProcessingService service = new IngestBatchProcessingService(mapper, provider);

        assertThat(service.process(new IngestBatchEvent("event-2", RabbitTopologyConfig.INGEST_ROUTE, 7, 3, 1)))
                .isEqualTo(IngestBatchProcessingService.ProcessResult.PROCESSED);
        verify(submitter).submit(new IngestBatchEvent("event-2", RabbitTopologyConfig.INGEST_ROUTE, 7, 3, 1),
                List.of(record));
    }

    @Test
    void missingInferenceSubmitterFailsClosedWithoutMarkingMessageConsumed() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<InferenceTaskSubmitter> provider = mock(ObjectProvider.class);
        when(mapper.findAcceptedRecords(7)).thenReturn(List.of());
        when(provider.getIfAvailable()).thenReturn(null);
        IngestBatchProcessingService service = new IngestBatchProcessingService(mapper, provider);

        assertThatThrownBy(() -> service.process(
                new IngestBatchEvent("event-3", RabbitTopologyConfig.INGEST_ROUTE, 7, 3, 0)))
                .isInstanceOf(RetryableConsumerException.class)
                .hasMessage("INFERENCE_TASK_SUBMITTER_UNAVAILABLE");
        verify(mapper, never()).markConsumed(IngestBatchProcessingService.CONSUMER_NAME, "event-3");
    }

    @Test
    void sixthRecordedFailureIsMarkedDeadLetteredAfterFiveRetries() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<InferenceTaskSubmitter> provider = mock(ObjectProvider.class);
        when(mapper.findConsumedMessageForUpdate(IngestBatchProcessingService.CONSUMER_NAME, "event-5"))
                .thenReturn(new IngestMapper.ConsumedMessageRow(1, IngestBatchProcessingService.CONSUMER_NAME,
                        "event-5", "retrying", 5, "TEMPORARY", "retry", Instant.now()));
        IngestBatchProcessingService service = new IngestBatchProcessingService(mapper, provider);

        assertThat(service.recordFailure("event-5", "TEMPORARY", "temporary failure", false))
                .isEqualTo(new IngestBatchProcessingService.FailureResult(6, "dead_lettered"));
        verify(mapper).recordConsumedFailure(eq(IngestBatchProcessingService.CONSUMER_NAME), eq("event-5"),
                eq("dead_lettered"), eq("TEMPORARY"), any());
    }

    @Test
    void failureAfterConcurrentSuccessKeepsConsumedStatus() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<InferenceTaskSubmitter> provider = mock(ObjectProvider.class);
        when(mapper.findConsumedMessageForUpdate(IngestBatchProcessingService.CONSUMER_NAME, "event-6"))
                .thenReturn(new IngestMapper.ConsumedMessageRow(1, IngestBatchProcessingService.CONSUMER_NAME,
                        "event-6", "consumed", 0, null, null, Instant.now()));
        IngestBatchProcessingService service = new IngestBatchProcessingService(mapper, provider);

        assertThat(service.recordFailure("event-6", "TEMPORARY", "temporary failure", false).alreadyConsumed())
                .isTrue();
        verify(mapper, never()).recordConsumedFailure(any(), any(), any(), any(), any());
        verify(mapper, never()).insertConsumedFailureRow(any(), any(), any(), any(), any());
    }
}
