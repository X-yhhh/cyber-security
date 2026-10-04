package com.xyh.cybersecurity.model.runtime;

import com.xyh.cybersecurity.model.release.ModelMapper;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/** 进程启动时恢复已批准的本机活动模型。 */
@Mapper
public interface ModelRuntimeMapper {
    List<ModelMapper.ModelRow> listActiveDeployments();
}
