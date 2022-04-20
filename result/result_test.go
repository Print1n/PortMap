package result

import (
	"testing"
	"time"
)

func TestNewStandardWriter(t *testing.T) {
	writer, err := NewStandardWriter(false, true)
	if err != nil {
		t.Logf("new writer error :%s\n", err.Error())
	}
	even := &Event{
		Target:       "192.168.0.53",
		Time:         time.Now().Format("2006-01-02 15:04:05"),
		WorkingEvent: "time out",
	}
	writer.Write(even)
}
