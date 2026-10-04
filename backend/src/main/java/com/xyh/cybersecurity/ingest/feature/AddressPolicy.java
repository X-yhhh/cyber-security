package com.xyh.cybersecurity.ingest.feature;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 规格 §1.2 的地址分类：判定流是否排除、地址族与本机视角。只解析 IP 字面量（{@link InetAddress#ofLiteral}），
 * 不做 DNS 查询。
 *
 * <p>定向广播有两种口径：传感器按接口子网（CIDR）判定；UNSW 回放没有接口掩码，按规格 §1.2 最后一段
 * 以「末字节为 255」判定（UNSW 各子网为 /24）。两者都只适用于 IPv4。</p>
 */
public final class AddressPolicy {
    private final Set<InetAddress> localAddresses;
    private final List<Subnet> localSubnets;
    private final boolean lastOctet255IsBroadcast;

    private AddressPolicy(Set<InetAddress> localAddresses, List<Subnet> localSubnets, boolean lastOctet255IsBroadcast) {
        if (localAddresses.isEmpty()) throw new IllegalArgumentException("至少需要一个本机地址");
        this.localAddresses = Set.copyOf(localAddresses);
        this.localSubnets = List.copyOf(localSubnets);
        this.lastOctet255IsBroadcast = lastOctet255IsBroadcast;
    }

    /**
     * 传感器口径。
     *
     * @param localAddresses 本机在授权接口上的地址
     * @param ipv4Subnets    本机接口的 IPv4 子网（CIDR，如 {@code 192.0.2.0/24}），用于定向广播判定
     */
    public static AddressPolicy forSensor(Set<String> localAddresses, List<String> ipv4Subnets) {
        return new AddressPolicy(localAddresses.stream().map(AddressPolicy::parse).collect(java.util.stream.Collectors.toSet()),
                ipv4Subnets.stream().map(Subnet::parse).toList(), false);
    }

    /** UNSW 回放口径：以指定主机为传感器所在主机，定向广播按末字节 255 判定（规格 §1.2）。 */
    public static AddressPolicy unswReplay(String sensorHost) {
        return new AddressPolicy(Set.of(parse(sensorHost)), List.of(), true);
    }

    /**
     * 分类一条流。
     *
     * @return 排除时返回原因；否则返回地址族与视角
     */
    public Classification classify(String initiator, String responder) {
        InetAddress src = tryParse(initiator);
        InetAddress dst = tryParse(responder);
        if (src == null || dst == null || src.getClass() != dst.getClass()) return Classification.excluded("invalid_address");
        if (dst.isMulticastAddress()) return Classification.excluded("multicast_destination");
        if (isBroadcast(dst)) return Classification.excluded("broadcast_destination");
        if (dst.isLoopbackAddress()) return Classification.excluded("loopback_destination");
        if (dst.isAnyLocalAddress()) return Classification.excluded("unspecified_destination");
        String family = dst instanceof Inet4Address ? "ipv4" : "ipv6";
        // 两端都是本机时按响应方处理，与训练端 recompute_ct 以 dstip 为传感器主机的口径一致。
        if (localAddresses.contains(dst)) return Classification.included(family, "responder", src, dst);
        if (localAddresses.contains(src)) return Classification.included(family, "initiator", src, dst);
        return Classification.excluded("no_local_endpoint");
    }

    private boolean isBroadcast(InetAddress address) {
        if (!(address instanceof Inet4Address)) return false;
        byte[] bytes = address.getAddress();
        if ((bytes[0] & bytes[1] & bytes[2] & bytes[3] & 0xff) == 0xff) return true;
        if (lastOctet255IsBroadcast && (bytes[3] & 0xff) == 0xff) return true;
        return localSubnets.stream().anyMatch(subnet -> subnet.isBroadcast(bytes));
    }

    private static InetAddress parse(String literal) {
        InetAddress address = tryParse(literal);
        if (address == null) throw new IllegalArgumentException("不是合法的 IP 字面量");
        return address;
    }

    private static InetAddress tryParse(String literal) {
        if (literal == null || literal.isBlank() || literal.length() > 64) return null;
        try {
            return InetAddress.ofLiteral(literal.trim());
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    /**
     * 分类结果。排除时 {@code exclusion} 非空，其余为空。
     *
     * @param viewpoint {@code responder}（本机是响应方）或 {@code initiator}
     */
    public record Classification(Optional<String> exclusion, String addressFamily, String viewpoint,
                                 InetAddress initiator, InetAddress responder) {
        static Classification excluded(String reason) {
            return new Classification(Optional.of(reason), null, null, null, null);
        }

        static Classification included(String family, String viewpoint, InetAddress initiator, InetAddress responder) {
            return new Classification(Optional.empty(), family, viewpoint, initiator, responder);
        }
    }

    private record Subnet(int network, int mask) {
        static Subnet parse(String cidr) {
            String[] parts = cidr == null ? new String[0] : cidr.split("/", -1);
            if (parts.length != 2 || !parts[1].matches("\\d{1,2}")) throw new IllegalArgumentException("CIDR 格式无效");
            InetAddress address = tryParse(parts[0]);
            int prefix = Integer.parseInt(parts[1]);
            if (!(address instanceof Inet4Address) || prefix < 1 || prefix > 30) {
                throw new IllegalArgumentException("只支持 /1～/30 的 IPv4 子网");
            }
            int mask = -1 << (32 - prefix);
            return new Subnet(toInt(address.getAddress()) & mask, mask);
        }

        boolean isBroadcast(byte[] address) {
            int value = toInt(address);
            return (value & mask) == network && (value | mask) == -1;
        }

        private static int toInt(byte[] bytes) {
            return (bytes[0] & 0xff) << 24 | (bytes[1] & 0xff) << 16 | (bytes[2] & 0xff) << 8 | (bytes[3] & 0xff);
        }
    }
}
