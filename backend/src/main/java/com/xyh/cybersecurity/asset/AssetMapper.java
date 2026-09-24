package com.xyh.cybersecurity.asset;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 在 SQL 内将资产结果限定为主体对 asset.read 明确获授的范围。 */
@Mapper
public interface AssetMapper {

    long countVisible(@Param("userId") long userId);

    List<AssetView> listVisible(@Param("userId") long userId,
                                @Param("offset") int offset,
                                @Param("limit") int limit);

    AssetView findVisible(@Param("userId") long userId, @Param("assetId") long assetId);

    int updateVisible(@Param("userId") long userId, @Param("assetId") long assetId,
                      @Param("criticality") String criticality, @Param("owner") String owner,
                      @Param("status") String status);

    record AssetView(long id, String assetKey, String assetType, String environment,
                     String criticality, String owner, String status) { }
}
