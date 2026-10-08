package com.xyh.cybersecurity.guard;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

import static com.xyh.cybersecurity.guard.GuardJson.parse;
import static org.assertj.core.api.Assertions.assertThat;

/** B2 合成样例通过真实后端契约；合成资格不代表 G3 或真实部署已获准。 */
class GuardComposedPolicyTest {
    @Test void generatedPoliciesPassRuntimeContract() throws Exception {
        var contracts = new GuardContracts();
        var folder = Path.of("../scripts/p7/testdata");
        var alert = parse(Files.readString(folder.resolve("evaluated-policy.json")));
        contracts.policy(alert);
        assertThat(alert.path("mode").asText()).isEqualTo("alert_only");
        var automatic = parse(Files.readString(folder.resolve("composed-policy.json")));
        contracts.policy(automatic);
        assertThat(automatic.path("mode").asText()).isEqualTo("auto");
        assertThat(automatic.path("familyPolicies").get(0).path("autoEligible").asBoolean()).isTrue();
        assertThat(automatic.path("familyPolicies").get(0).path("modelAutoEligible").asBoolean()).isFalse();
        assertThat(automatic.path("rulePolicies").get(0).path("autoEligible").asBoolean()).isTrue();
        var protection = parse(Files.readString(folder.resolve("protection-set.json")));
        assertThat(automatic.path("protectionSetSha256").asText()).isEqualTo(GuardJson.hash(protection));
    }
}
