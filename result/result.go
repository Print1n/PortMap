package result

import (
	"bytes"
	"fmt"
	"github.com/Print1n/PortMap/Ginfo/Ghttp"
	"github.com/Print1n/PortMap/conversion"
	"github.com/fatih/color"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/shiena/ansicolor"
	"io"
	"os"
	"strings"
	"time"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	// Write writes the event to file and/or screen.
	Write(*Event) error
}

type Info struct {
	Banner  string
	Service string
	Cert    string
	Target  string
}

type Event struct {
	WorkingEvent interface{} `json:"WorkingEvent"`
	Info         *Info       `json:"info,inline"`
	Time         string      `json:"time"`
	Target       string      `json:"Target"`
}

type StandardWriter struct {
	w    io.Writer
	json bool
}

func NewStandardWriter(nocolor, json bool) (*StandardWriter, error) {
	w := ansicolor.NewAnsiColorWriter(os.Stdout)
	if nocolor {
		color.NoColor = true
	}

	writer := &StandardWriter{
		w:    w,
		json: json,
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *Event) error {
	if event == nil {
		return nil
	}
	event.Time = time.Now().Format("2006-01-02 15:04:05")

	var data []byte
	var err error
	if w.json {
		data, err = w.formatJSON(event)
	} else {
		data = w.formatScreen(event)
	}

	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}

	_, _ = w.w.Write(data)
	_, _ = w.w.Write([]byte("\n"))

	return nil
}

func (w *StandardWriter) formatJSON(output *Event) ([]byte, error) {
	return jsoniter.Marshal(output)
}

// formatScreen formats the output for showing on screen.
func (w *StandardWriter) formatScreen(output *Event) []byte {
	builder := &bytes.Buffer{}
	builder.WriteString(color.RedString(fmt.Sprintf("%-20s", output.Target)))
	builder.WriteString(" ")
	if output.Info.Service != "unknown" {
		builder.WriteString(color.YellowString(output.Info.Service))
	}

	if output.Info.Service == "ssl/tls" || output.Info.Service == "http" {
		if len(output.Info.Cert) > 0 {
			builder.WriteString(" [")
			builder.WriteString(color.YellowString(output.Info.Cert))
			builder.WriteString("]")
		}
	}
	// http、ssl/tls的WorkingEvent不为nil
	if output.WorkingEvent != nil {
		switch tmp := output.WorkingEvent.(type) {
		case Ghttp.Result:
			httpBanner := tmp.ToString()
			if len(httpBanner) > 0 {
				builder.WriteString(" | ")
				builder.WriteString(color.GreenString(httpBanner))
			}
		default:
			result := conversion.ToString(tmp)
			if strings.HasPrefix(result, "\\x") == false && len(result) > 0 {
				builder.WriteString(" | ")
				builder.WriteString(color.GreenString(result))
			}
		}
	} else {
		if strings.HasPrefix(output.Info.Banner, "\\x") == false && len(output.Info.Banner) > 0 {
			r := strings.Split(output.Info.Banner, "\\x0d\\x0a")
			builder.WriteString(" | ")
			builder.WriteString(color.GreenString(r[0]))
		}
	}
	return builder.Bytes()
}
