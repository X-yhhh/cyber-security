package com.xyh.cybersecurity.ingest.contract;

/**
 * 流记录的非特征元数据（规格 §1.1、§1.2）。不进入 {@code features}，不参与模型输入。
 *
 * <p>用于判定记录是否在激活模型的评估范围内（{@code supported_viewpoints}、{@code supported_address_families}）。
 * 范围外的记录仍可入库和进窗口，但不推理，状态记 {@code not_in_model_scope}。</p>
 *
 * @param viewpoint     本机在该流中的角色：{@code responder} 或 {@code initiator}
 * @param addressFamily {@code ipv4} 或 {@code ipv6}
 * @param handshakeSeen TCP 流首包是否为纯 SYN；看不到握手时方向可能判反（规格 §1.1、§7）
 */
public record RecordMetadata(String viewpoint, String addressFamily, Boolean handshakeSeen) { }
