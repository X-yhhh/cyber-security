package com.xyh.cybersecurity.ops;

import org.apache.ibatis.annotations.Mapper;

/** 就绪探针的最小数据库查询。 */
@Mapper
public interface HealthMapper {
    int ping();
}
