package com.xyh.cybersecurity.authorization;

import com.xyh.cybersecurity.common.api.ApiRequestException;

/** 解析可授予的资源范围；范围只接受数据库支持的稳定资源类型和标识。 */
public record ResourceScope(Type type, String id) {

    public enum Type {
        GLOBAL("global"), ASSET("asset"), DATA_SOURCE("data_source"), MODEL_REGISTRY("model_registry");

        private final String key;

        Type(String key) { this.key = key; }
        public String key() { return key; }

        public static Type parse(String value) {
            for (Type type : values()) {
                if (type.key.equals(value)) {
                    return type;
                }
            }
            throw ApiRequestException.badRequest("授权范围类型无效");
        }
    }

    public static ResourceScope parse(String typeValue, String idValue, String roleKey) {
        if (typeValue == null || idValue == null || idValue.isBlank()) {
            throw ApiRequestException.badRequest("授权范围不能为空");
        }
        Type type = Type.parse(typeValue);
        if (type == Type.GLOBAL) {
            if (!"*".equals(idValue) || !"platform_admin".equals(roleKey)) {
                throw ApiRequestException.badRequest("全局范围仅允许平台管理员角色且标识必须为 *");
            }
            return new ResourceScope(type, "*");
        }
        if ("*".equals(idValue) || idValue.length() > 128) {
            throw ApiRequestException.badRequest("资源范围标识无效");
        }
        if (type == Type.ASSET || type == Type.DATA_SOURCE) {
            try {
                long id = Long.parseLong(idValue);
                if (id < 1) {
                    throw new NumberFormatException();
                }
                idValue = Long.toString(id);
            } catch (NumberFormatException exception) {
                throw ApiRequestException.badRequest("资产和数据源范围必须使用正整数标识");
            }
        }
        return new ResourceScope(type, idValue);
    }
}
