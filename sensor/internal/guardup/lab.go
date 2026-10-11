package guardup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// LabRun 只使用 machine.sensor.read 读取该传感器的会话交接，不增加写入/执行权限。
// 此扩展不改变批次、心跳或 spool 协议；原始 data 由 lab 适配器严格核验。
func (c *Client) LabRun(ctx context.Context, runID string) (json.RawMessage, error) {
	if !uuidPattern.MatchString(runID) {
		return nil, errors.New("LAB_RUN_ID_INVALID")
	}
	var raw json.RawMessage
	err := c.do(ctx, http.MethodGet, "lab-validation-runs/"+runID, "", nil, http.StatusOK, &raw)
	return raw, err
}
