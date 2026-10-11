package guardlab

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardup"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

// TestExportHealthFixture 是 Java 隔离联调的合成数据出口，默认不写文件。
// 只调用 S4 观察器；不打开接口、不制造报文、不把合成窗口作为现场证明。
func TestExportHealthFixture(t *testing.T) {
	request := os.Getenv("GUARD_HEALTH_FIXTURE_REQUEST")
	if request == "" {
		t.Skip("only used by isolated Java integration")
	}
	var input struct {
		Identity capturehealth.Identity `json:"identity"`
		Start    time.Time              `json:"start"`
		Count    int                    `json:"count"`
	}
	b, e := ReadPrivate(request)
	if e != nil || Decode(b, &input) != nil || input.Count < 1 || input.Count > 128 {
		t.Fatal("invalid synthetic request")
	}
	var windows []capturehealth.Window
	var hashes []string
	observer, e := capturehealth.New(input.Identity, capturehealth.Options{Window: 5 * time.Second, Skew: func() (int64, bool) { return 0, true }, NewID: guardup.NewUUID, Emit: func(w capturehealth.Window) error {
		h, e := jcs.SHA256(w)
		windows = append(windows, w)
		hashes = append(hashes, h)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i <= input.Count; i++ {
		if e = observer.Observe(hostguard.LiveSample{At: input.Start.Add(time.Duration(i) * 5 * time.Second), PacketsSeen: uint64(i * 3), DropsKnown: true}); e != nil {
			t.Fatal(e)
		}
	}
	b, _ = json.Marshal(map[string]any{"synthetic": true, "windows": windows, "hashes": hashes})
	f, e := os.OpenFile(os.Getenv("GUARD_HEALTH_FIXTURE_OUTPUT"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal("invalid synthetic output")
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
}
