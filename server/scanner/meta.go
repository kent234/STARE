package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// SchemaVersion фиксирует формат ScanResult. Меняется при несовместимых
// изменениях JSON; аддитивные поля версию не требуют.
const SchemaVersion = "1.1.0"

// Состояния инструмента. "missing" и "skipped" — разные вещи:
// первый означает отсутствие бинарника, второй — сознательный пропуск
// (например, приватная цель).
const (
	ToolRan     = "ran"
	ToolMissing = "missing"
	ToolError   = "error"
	ToolSkipped = "skipped"
)

// ToolStatus — что реально произошло с внешним инструментом.
// Без этого пустые vulnerabilities/tls/cloud_buckets неотличимы от «не проверяли».
type ToolStatus struct {
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Input      int    `json:"input,omitempty"`
	Items      int    `json:"items,omitempty"`
	Dropped    int    `json:"dropped,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Error      string `json:"error,omitempty"`
}

// StageCoverage — сколько целей реально удалось обработать на каждой стадии.
// Attempted > Succeeded означает не «сервиса нет», а «мы не дошли/не смогли».
type StageCoverage struct {
	Attempted int `json:"attempted"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed,omitempty"`
	Skipped   int `json:"skipped,omitempty"`
}

// ScanMeta — машинно-читаемая телеметрия скана.
type ScanMeta struct {
	Tools    map[string]ToolStatus    `json:"tools,omitempty"`
	Coverage map[string]StageCoverage `json:"coverage,omitempty"`
	Versions map[string]string        `json:"versions,omitempty"`
}

// NewScanID возвращает случайный идентификатор прогона для аудита/диффов.
func NewScanID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(buf)
}

func newScanMeta() ScanMeta {
	return ScanMeta{
		Tools:    map[string]ToolStatus{},
		Coverage: map[string]StageCoverage{},
		Versions: map[string]string{},
	}
}
