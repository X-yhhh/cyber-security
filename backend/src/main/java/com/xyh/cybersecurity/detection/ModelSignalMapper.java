package com.xyh.cybersecurity.detection;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

/** 信号升级当前读与条件更新；调用方必须持有资产锁，所有写入参加消费事务。 */
@Mapper
public interface ModelSignalMapper {
    List<Row> context(@Param("asset") long asset, @Param("from") Instant from, @Param("to") Instant to,
                      @Param("severityVersion") String severityVersion, @Param("correlationVersion") String correlationVersion,
                      @Param("limit") int limit);
    int promote(@Param("id") long id, @Param("severity") String severity, @Param("basis") String basis, @Param("now") Instant now);
    record Row(long id, long recordId, Instant eventTime, String contractVersion, String alertType,
               String alertLayer, BigDecimal score) { }
}
