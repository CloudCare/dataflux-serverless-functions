package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/metric"
	"github.com/influxdata/telegraf/plugins/serializers/influx"
)

const (
	EventType_Unsupport = iota
	EventType_CloudwatchLog
	EventType_CloudwatchEvent
	EventType_S3Event
)

var (
	datawayUrl  = ""
	enableDebug = false

	custemHttpHeaders map[string]string
)

func parseEventType(ev interface{}) (interface{}, int) {

	evType := EventType_Unsupport

	if mv, ok := ev.(map[string]interface{}); ok {

		if enableDebug {
			log.Printf("[DataFlux] raw input data: %s", mv)
		}

		if records, ok := mv["Records"]; ok {
			if arr, ok := records.([]interface{}); ok {
				if len(arr) > 0 {
					if record, ok := arr[0].(map[string]interface{}); ok {
						if _, ok = record["s3"]; ok {
							evType = EventType_S3Event
						}
					}
				}
			}
		} else if _, ok = mv["awslogs"]; ok {
			evType = EventType_CloudwatchLog
		} else if _, ok = mv["detail"]; ok {
			evType = EventType_CloudwatchEvent
		}
	}

	if evType == EventType_Unsupport {
		return nil, evType
	}

	var cwlog events.CloudwatchLogsEvent
	var cwev events.CloudWatchEvent
	var s3ev events.S3Event

	data, err := json.Marshal(ev)
	if err != nil {
		if enableDebug {
			log.Printf("[error] fail to marshal event, %s", err)
		}
		return nil, EventType_Unsupport
	}

	switch evType {
	case EventType_CloudwatchLog:
		if json.Unmarshal(data, &cwlog); err == nil {
			return &cwlog, evType
		} else {
			if enableDebug {
				log.Printf("[error] fail to unmarshal CloudwatchLogsEvent, %s", err)
			}
		}
	case EventType_CloudwatchEvent:
		if err = json.Unmarshal(data, &cwev); err == nil {
			return &cwev, evType
		} else {
			if enableDebug {
				log.Printf("[error] fail to unmarshal CloudWatchEvent, %s", err)
			}
		}
	case EventType_S3Event:
		if err = json.Unmarshal(data, &s3ev); err == nil {
			return &s3ev, evType
		} else {
			if enableDebug {
				log.Printf("[error] fail to unmarshal S3Event, %s", err)
			}
		}
	}

	return nil, EventType_Unsupport

}

func awslogHandler(lctx *lambdacontext.LambdaContext, ev *events.CloudwatchLogsEvent) error {

	logdata, err := ev.AWSLogs.Parse()
	if err != nil {
		return fmt.Errorf("[DataFlux] fail to parse aws logs, %s", err)
	}

	var logMetrics []telegraf.Metric

	for _, le := range logdata.LogEvents {
		tags := map[string]string{
			"LogGroup": logdata.LogGroup,
			"$app":     logdata.LogStream,
		}

		fields := map[string]interface{}{}
		fields["$content"] = le.Message

		metricName := fmt.Sprintf("$log_%s", logdata.LogStream)

		m, err := metric.New(metricName, tags, fields, time.Unix(le.Timestamp/1000, 0))
		if err != nil {
			log.Printf("[DataFlux] Fail to make metric, %s", err)
		} else {
			logMetrics = append(logMetrics, m)
		}

	}

	return sendMetrics(logMetrics)
}

func cwEventHandler(lctx *lambdacontext.LambdaContext, ev *events.CloudWatchEvent) error {

	tags := map[string]string{
		"DetailType": ev.DetailType,
		"AccountID":  ev.AccountID,
		"Region":     ev.Region,
	}

	if ev.Source != "" {
		tags["$source"] = ev.Source
	} else {
		tags["$source"] = "cloudwatch"
	}

	fields := map[string]interface{}{
		"$title": "cloudwatch_event",
	}
	if ev.Detail != nil {
		fields["Detail"] = string(ev.Detail)
	}

	var evMetrics []telegraf.Metric
	m, err := metric.New(`$keyevent`, tags, fields, ev.Time)
	if err != nil {
		log.Printf("[DataFlux] Fail to make metric, %s", err)
	} else {
		evMetrics = append(evMetrics, m)
	}
	return sendMetrics(evMetrics)
}

func s3EventHandler(lctx *lambdacontext.LambdaContext, ev *events.S3Event) error {

	var evMetrics []telegraf.Metric
	for _, record := range ev.Records {

		tags := map[string]string{
			"$source":     record.EventSource,
			"Bucket":      record.S3.Bucket.Name,
			"Region":      record.AWSRegion,
			"PrincipalID": record.PrincipalID.PrincipalID,
		}

		fields := map[string]interface{}{
			"$title":          record.EventName,
			"Object":          record.S3.Object.Key,
			"ObjectSize":      record.S3.Object.Size,
			"ObjectVersion":   record.S3.Object.VersionID,
			"ObjectETag":      record.S3.Object.ETag,
			"SourceIPAddress": record.RequestParameters.SourceIPAddress,
		}

		m, err := metric.New(`$keyevent`, tags, fields, record.EventTime)
		if err != nil {
			log.Printf("[DataFlux] Fail to make metric, %s", err)
		} else {
			evMetrics = append(evMetrics, m)
		}
	}
	return sendMetrics(evMetrics)
}

func snsEventHandler(ev *events.SNSEvent) error {
	log.Printf("snsEventHandler")
	return nil
}

func kinesisEventHandler(ev *events.KinesisEvent) error {
	log.Printf("kinesisEventHandler")
	return nil
}

func HandleRequest(ctx context.Context, ev interface{}) error {

	if os.Getenv("DATAFLUX_DEBUG") == "true" {
		enableDebug = true
	}

	datawayUrl = os.Getenv("DATAFLUX_DATAWAY_URL")
	if datawayUrl == "" {
		return fmt.Errorf("[DataFlux] dataway url not found")
	}

	if enableDebug {
		log.Printf("[DataFlux] dataway: %s", datawayUrl)
	}

	lc, _ := lambdacontext.FromContext(ctx)

	event, evType := parseEventType(ev)

	switch evType {
	case EventType_CloudwatchLog:
		return awslogHandler(lc, event.(*events.CloudwatchLogsEvent))
	case EventType_CloudwatchEvent:
		return cwEventHandler(lc, event.(*events.CloudWatchEvent))
	case EventType_S3Event:
		return s3EventHandler(lc, event.(*events.S3Event))
	default:
	}

	return fmt.Errorf("[DataFlux] Event type not supported")
}

func sendMetrics(metrics []telegraf.Metric) error {

	if len(metrics) == 0 {
		return nil
	}

	serializer := influx.NewSerializer()

	for _, metric := range metrics {
		tags := metric.Tags()
		for k, v := range tags {
			if v != "" && v[len(v)-1] == '\\' {
				v += " "
				metric.RemoveTag(k)
				metric.AddTag(k, v)
			}
		}
	}

	reqBody, err := serializer.SerializeBatch(metrics)
	if err != nil {
		return err
	}

	var reqBodyBuffer io.Reader = bytes.NewBuffer(reqBody)

	rc, err := compressWithGzip(reqBodyBuffer)
	if err != nil {
		return err
	}
	defer rc.Close()
	reqBodyBuffer = rc

	req, err := http.NewRequest(http.MethodPost, datawayUrl, reqBodyBuffer)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "dataflux-aws-lambda")
	req.Header.Set("Content-Type", `text/plain; charset=utf-8`)
	req.Header.Set("Content-Encoding", "gzip")

	for k, v := range custemHttpHeaders {
		if strings.ToLower(k) == "host" {
			req.Host = v
		}
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("[DataFlux] when writing to [%s] received status code: %d, body: %s", datawayUrl, resp.StatusCode, string(body))
	} else {
		if enableDebug {
			log.Printf("[DataFlux] send %d metrics ok", len(metrics))
		}
	}

	return nil
}

func main() {
	lambda.Start(HandleRequest)
}

type readWaitCloser struct {
	pipeReader *io.PipeReader
	wg         sync.WaitGroup
}

func compressWithGzip(data io.Reader) (io.ReadCloser, error) {
	pipeReader, pipeWriter := io.Pipe()
	gzipWriter := gzip.NewWriter(pipeWriter)

	rc := &readWaitCloser{
		pipeReader: pipeReader,
	}

	rc.wg.Add(1)
	var err error
	go func() {
		_, err = io.Copy(gzipWriter, data)
		gzipWriter.Close()
		pipeWriter.CloseWithError(err)
		rc.wg.Done()
	}()

	return pipeReader, err
}
