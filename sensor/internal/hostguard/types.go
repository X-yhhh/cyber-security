// Package hostguard 实现独立 v5 因果提取，不依赖 v4 完成流窗口，也不执行防火墙动作。
package hostguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const Version = "host-guard/5.0.0-rc.2"
const ReorderDelay = 100 * time.Millisecond

// FeatureProfileSHA256 是本提取器实现的 docs/contracts/feature-profile.json 原字节 SHA-256。
// 上传前必须与已批准传感器配置的 profileSha256 一致，不一致则拒绝上传而不是沿用服务端值。
const FeatureProfileSHA256 = "3bdeb637e46a9fde6192a20e58eacbe56563a9d21339860c54db4907fb8853b5"

type Features struct {
	ElapsedMs       float64  `json:"elapsedMs"`
	BytesOutbound   int64    `json:"bytesOutbound"`
	BytesInbound    int64    `json:"bytesInbound"`
	PacketsOutbound int64    `json:"packetsOutbound"`
	PacketsInbound  int64    `json:"packetsInbound"`
	LengthMin       int      `json:"lengthMin"`
	LengthMax       int      `json:"lengthMax"`
	LengthMean      float64  `json:"lengthMean"`
	LengthStd       float64  `json:"lengthStd"`
	IATMeanUs       *float64 `json:"iatMeanUs"`
	IATStdUs        *float64 `json:"iatStdUs"`
	SynCount        *int64   `json:"synCount"`
	SynAckCount     *int64   `json:"synAckCount"`
	RstCount        *int64   `json:"rstCount"`
	FinCount        *int64   `json:"finCount"`
	HandshakeSeen   *bool    `json:"handshakeSeen"`
}

type Context struct {
	WindowSeconds            int     `json:"windowSeconds"`
	CoverageMs               float64 `json:"coverageMs"`
	PeerFlowStarts           int64   `json:"peerFlowStarts"`
	PeerSynCount             int64   `json:"peerSynCount"`
	PeerRstCount             int64   `json:"peerRstCount"`
	PeerDistinctServicePorts int     `json:"peerDistinctServicePorts"`
	HostFlowStarts           int64   `json:"hostFlowStarts"`
	HostDistinctPeers        int     `json:"hostDistinctPeers"`
	PeerBytesOutbound        int64   `json:"peerBytesOutbound"`
	PeerBytesInbound         int64   `json:"peerBytesInbound"`
}

type Quality struct {
	CaptureGap       bool     `json:"captureGap"`
	LatePacket       bool     `json:"latePacket"`
	Truncated        bool     `json:"truncated"`
	OffloadSuspected bool     `json:"offloadSuspected"`
	CapacityDrop     bool     `json:"capacityDrop"`
	ClockSkewMs      *float64 `json:"clockSkewMs"`
}

func (q Quality) Defective() bool {
	return q.CaptureGap || q.LatePacket || q.Truncated || q.OffloadSuspected || q.CapacityDrop
}
func (q *Quality) merge(v Quality) {
	q.CaptureGap = q.CaptureGap || v.CaptureGap
	q.LatePacket = q.LatePacket || v.LatePacket
	q.Truncated = q.Truncated || v.Truncated
	q.OffloadSuspected = q.OffloadSuspected || v.OffloadSuspected
	q.CapacityDrop = q.CapacityDrop || v.CapacityDrop
}

type Observation struct {
	ContractVersion    string     `json:"contractVersion"`
	ObservationID      string     `json:"observationId"`
	AssetID            string     `json:"assetId"`
	SensorID           string     `json:"sensorId"`
	BootID             string     `json:"bootId"`
	CaptureScopeID     string     `json:"captureScopeId"`
	FlowID             string     `json:"flowId"`
	ParentConnectionID string     `json:"parentConnectionId"`
	SnapshotIndex      int        `json:"snapshotIndex"`
	Profile            string     `json:"profile"`
	Environment        string     `json:"environment"`
	FirstSeenAt        time.Time  `json:"firstSeenAt"`
	LastPacketAt       time.Time  `json:"lastPacketAt"`
	AsOf               time.Time  `json:"asOf"`
	EmittedAt          time.Time  `json:"emittedAt"`
	AddressFamily      string     `json:"addressFamily"`
	Transport          string     `json:"transport"`
	Direction          string     `json:"direction"`
	ServiceClass       string     `json:"serviceClass"`
	ServicePort        *uint16    `json:"servicePort"`
	PeerKey            string     `json:"peerKey"`
	KeyEpoch           int        `json:"keyEpoch"`
	TargetRef          *string    `json:"targetRef"`
	TargetExpiresAt    *time.Time `json:"targetExpiresAt"`
	Features           Features   `json:"features"`
	Contexts           []Context  `json:"contexts"`
	Quality            Quality    `json:"quality"`
	CloseReason        *string    `json:"closeReason"`
}

// Endpoints 仅供本地引用和受控离线标签账本；不得随 Observation 上传。
type Endpoints struct {
	Local, Peer netip.AddrPort
	Protocol    uint8
}
type Emission struct {
	Observation Observation
	Endpoints   Endpoints
}

// Config 为一个捕获域配置；地址列表改变必须新建引擎/boot，禁止在活动流中替换身份。
type Config struct {
	AssetID, SensorID, BootID, CaptureScopeID                      string
	Environment                                                    string
	KeyEpoch                                                       int
	PeerSecret                                                     []byte
	LocalAddresses                                                 []netip.Addr
	MTU                                                            int
	MaxFlows, MaxConnections, MaxBufferedPackets, MaxContextEvents int
	ClockSkewMs                                                    *float64
	Emit                                                           func(Emission) error
	// Lease 仅在已验证头、明确 TCP 方向、新包及非 research 环境下调用。
	Lease func(Observation, Endpoints) (string, time.Time, error)
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (c *Config) validate() error {
	for _, v := range []string{c.AssetID, c.SensorID, c.BootID, c.CaptureScopeID} {
		if !uuidPattern.MatchString(v) {
			return fmt.Errorf("身份必须为小写 UUID")
		}
	}
	if c.Environment != "research" && c.Environment != "lab" && c.Environment != "authorized" {
		return fmt.Errorf("未知环境")
	}
	if len(c.PeerSecret) < 32 || c.KeyEpoch < 1 || len(c.LocalAddresses) == 0 || c.Emit == nil {
		return fmt.Errorf("缺少密钥/地址/输出配置")
	}
	for _, a := range c.LocalAddresses {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("非法本机地址")
		}
	}
	if c.MTU == 0 {
		c.MTU = 1500
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("非法 MTU")
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 100000
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 500000
	}
	if c.MaxBufferedPackets == 0 {
		c.MaxBufferedPackets = 100000
	}
	if c.MaxContextEvents == 0 {
		c.MaxContextEvents = 2000000
	}
	if min(c.MaxFlows, c.MaxConnections, c.MaxBufferedPackets, c.MaxContextEvents) < 1 {
		return fmt.Errorf("容量必须为正")
	}
	c.PeerSecret = append([]byte(nil), c.PeerSecret...)
	c.LocalAddresses = append([]netip.Addr(nil), c.LocalAddresses...)
	return nil
}

func uuidBytes(b []byte) string {
	b = append([]byte(nil), b[:16]...)
	b[6] = (b[6] & 15) | 0x40
	b[8] = (b[8] & 63) | 0x80
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return uuidBytes(b)
}

// pseudonym 使用有长度边界的 JSON 数组作域分隔，原始地址仅进入 HMAC，不写日志。
func pseudonym(secret []byte, parts ...any) string {
	b, _ := json.Marshal(parts)
	h := hmac.New(sha256.New, secret)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (c Config) id(kind string, seq uint64) string {
	d := pseudonym(c.PeerSecret, kind, c.AssetID, c.SensorID, c.BootID, c.CaptureScopeID, c.KeyEpoch, seq)
	b, _ := hex.DecodeString(d)
	return uuidBytes(b)
}
func (c Config) peer(a netip.Addr) string {
	return pseudonym(c.PeerSecret, "host-guard-peer-v1", c.AssetID, c.SensorID, c.KeyEpoch, a.Unmap().String())
}

func serviceClass(proto string, p *uint16) string {
	if p == nil {
		return "other"
	}
	switch *p {
	case 53:
		return "dns"
	case 80, 8080:
		if proto == "tcp" {
			return "web"
		}
	case 443:
		if proto == "tcp" || proto == "udp" {
			return "web"
		}
	case 22, 3389:
		return "remote_admin"
	case 25, 110, 143, 465, 587, 993, 995:
		return "mail"
	}
	return "other"
}
