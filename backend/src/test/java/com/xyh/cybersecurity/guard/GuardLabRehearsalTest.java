package com.xyh.cybersecurity.guard;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 合成模式只能关闭真实动作权限，不能绕过会话的撤销、终态、期限或超时。 */
class GuardLabRehearsalTest {
    @Test void stopExpiryAndTimeoutAreImmediate() {
        var now=Instant.parse("2030-01-01T00:00:00Z");
        var row=map("status","active");var run=map("status","running","last_activity_at",db(now),"stop_requested_at",null);
        var p=object("validFrom",now.minusSeconds(1).toString(),"validUntil",now.plusSeconds(120).toString(),"timeoutSeconds",60);
        assertThatCode(()->GuardLabRehearsal.requireRunning(row,run,p,now)).doesNotThrowAnyException();
        assertThatThrownBy(()->GuardLabRehearsal.requireRunning(row,run,p,now.plusSeconds(60))).hasMessageContaining("LAB_RUN_TIMED_OUT");
        assertThatThrownBy(()->GuardLabRehearsal.requireRunning(row,run,p,now.plusSeconds(120))).hasMessageContaining("AUTHORIZATION_INACTIVE");
        run.put("stop_requested_at",db(now));
        assertThatThrownBy(()->GuardLabRehearsal.requireRunning(row,run,p,now)).hasMessageContaining("LAB_RUN_NOT_RUNNING");
        run.put("stop_requested_at",null);row.put("status","revoked");
        assertThatThrownBy(()->GuardLabRehearsal.requireRunning(row,run,p,now)).hasMessageContaining("LAB_RUN_NOT_RUNNING");
    }
}
