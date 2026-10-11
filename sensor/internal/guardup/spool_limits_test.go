package guardup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 记录上限扩展不能突破 1 MiB 请求体，也不能在提前封口时丢失或重复观察。
func TestSpoolCountAndByteLimitsPreserveAllObservations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		padding int
		want    []int
	}{{"count", 513, 1, []int{512, 1}}, {"bytes", 3, 600_000, []int{1, 1, 1}}} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenSpool(t.TempDir(), SpoolMeta{SensorID: sensorID, BootID: bootID, ConfigID: configID}, MaxBatchSize)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.count; i++ {
				raw, _ := json.Marshal(map[string]any{"number": i, "padding": strings.Repeat("x", tc.padding)})
				if err := s.Append(raw, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Seal(); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(s.Dir(), "batch-*.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != len(tc.want) {
				t.Fatalf("批次数 %d，期望 %d", len(files), len(tc.want))
			}
			next := 0
			for i, p := range files {
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) > maxBatchBytes {
					t.Fatalf("请求体超限：%d", len(raw))
				}
				var batch Batch
				if err := json.Unmarshal(raw, &batch); err != nil {
					t.Fatal(err)
				}
				if len(batch.Observations) != tc.want[i] {
					t.Fatalf("批内条数 %d，期望 %d", len(batch.Observations), tc.want[i])
				}
				for _, observation := range batch.Observations {
					var value struct {
						Number int `json:"number"`
					}
					if err := json.Unmarshal(observation, &value); err != nil {
						t.Fatal(err)
					}
					if value.Number != next {
						t.Fatalf("观察次序 %d，期望 %d", value.Number, next)
					}
					next++
				}
			}
			if next != tc.count {
				t.Fatalf("观察总数 %d，期望 %d", next, tc.count)
			}
		})
	}
}

func TestSpoolRejectsOversizedSingleObservationWithoutWriting(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolMeta{SensorID: sensorID, BootID: bootID, ConfigID: configID}, MaxBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(strings.Repeat("x", maxBatchBytes))
	if err := s.Append(raw, time.Now()); err == nil || err.Error() != "SPOOL_OBSERVATION_TOO_LARGE" {
		t.Fatalf("未拒绝超大观察：%v", err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir(), "batch-*.json"))
	if len(files) != 0 {
		t.Fatal("拒绝后仍写入了批次")
	}
}
