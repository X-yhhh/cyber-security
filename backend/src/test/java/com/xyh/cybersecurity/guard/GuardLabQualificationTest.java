package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 类别登记与平台能力分离；正式事实可以逐类通过，合成事实永不授予等级。 */
class GuardLabQualificationTest {
    ObjectNode report() throws Exception { return (ObjectNode)GuardLabReport.generate(GuardLabReportTest.live()); }
    @Test void syntheticCannotRegisterEvenWhenMetricsPass() throws Exception {
        assertThat(GuardLabSessions.qualifiedSources(object("evidenceKind","synthetic"),report(),"completed")).isEmpty();
    }
    @Test void formalPassedSourcesAreRegisteredIndependently() throws Exception {
        var report=report();
        assertThat(GuardLabSessions.qualifiedSources(object("evidenceKind","lab"),report,"completed")).isNotEmpty();
        for(var item:report.path("scenarios"))if("dos_slow".equals(item.path("family").asText()))((ObjectNode)item).put("status","failed");
        report.put("passed",false);
        assertThat(GuardLabSessions.qualifiedSources(object("evidenceKind","lab"),report,"completed"))
                .noneMatch(s->"dos_slow".equals(s.path("family").asText()))
                .anyMatch(s->"brute_force".equals(s.path("family").asText()));
    }
    @Test void alertOnlySourceDoesNotInheritOtherSourcesEligibility() throws Exception {
        var report=report();
        var rows=(com.fasterxml.jackson.databind.node.ArrayNode)report.path("scenarios");
        var model=java.util.stream.StreamSupport.stream(rows.spliterator(),false)
                .filter(s->"brute_force".equals(s.path("family").asText())&&s.path("trialAutoEligible").asBoolean())
                .findFirst().orElseThrow().deepCopy();
        ((ObjectNode)model).put("source","rule").put("ruleId","alert-only").put("trialAutoEligible",false);
        rows.add(model);
        var sources=GuardLabSessions.qualifiedSources(object("evidenceKind","lab"),report,"completed");
        assertThat(sources).noneMatch(s->"rule:alert-only".equals(s.path("source").asText()));
        assertThat(sources).anyMatch(s->"model".equals(s.path("source").asText()));
    }
    @Test void commonSafetyEvidenceCannotBeSkipped() throws Exception {
        var manifest=object("evidenceKind","lab");var report=report();
        assertThat(GuardLabSessions.qualifiedSources(manifest,report,"interrupted")).isEmpty();
        ((ObjectNode)report.get("normal")).put("passed",false);
        assertThat(GuardLabSessions.qualifiedSources(manifest,report,"completed")).isEmpty();
        report=report();((com.fasterxml.jackson.databind.node.ArrayNode)report.get("unlinkedCommandIds")).add(id());
        assertThat(GuardLabSessions.qualifiedSources(manifest,report,"completed")).isEmpty();
        report=report();((ObjectNode)report.at("/scenarios/0/commands/0")).put("cleanup","unverified");
        assertThat(GuardLabSessions.qualifiedSources(manifest,report,"completed")).isEmpty();
    }
}
