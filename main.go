package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strconv"
	"sync"
	"time"

	uuid "github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.ibm.com/mhub/mhlog"
)

type (
	Config struct {
		Url                      *string
		HTTPTimeout              *int
		TLSTimeout               *int
		SleepTimeBetweenRequests *int
	}

	EventInformation struct {
		Txid string
		Addr string
		Msg  string
		Hook string
	}
)

var (
	acAddressCache = sync.Map{}
)

// ------------------------------------
// Public Functions
// ------------------------------------

func main() {
	logger := mhlog.NewConsoleLogger()
	config, err := readConfig()
	if err != nil {
		logger.Log("Failed to read config", mhlog.ErrorKey, err)
		os.Exit(1)
	}

	iamRequestCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "actest_iam_requests_total",
			Help: "Number of IAM API requests",
		},
		[]string{"code"},
	)

	iamRequestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "actest_iam_duration_seconds",
			Help:    "IAM API duration seconds",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 25, 50},
		},
		[]string{"code"},
	)

	dnsLatencyVec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "actest_iam_dns_duration_seconds",
			Help:    "Trace dns latency histogram.",
			Buckets: []float64{.01, .05, .1, .5, 1, 2.5},
		},
		[]string{"event"},
	)

	tlsLatencyVec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "actest_iam_tls_duration_seconds",
			Help:    "Trace tls latency histogram.",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 25, 50},
		},
		[]string{"event"},
	)

	connPoolCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "actest_iam_connections_total",
			Help: "Number of connections made to IAM",
		},
		[]string{"reused", "wasidle"},
	)

	connPoolInstrumenter := func(next http.RoundTripper) promhttp.RoundTripperFunc {
		return promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			trace := &httptrace.ClientTrace{
				GetConn: func(hostPort string) {
					logger.Log("get connection event [hp]", "hp", hostPort)
				},
				GotConn: func(info httptrace.GotConnInfo) {
					connPoolCounter.WithLabelValues(strconv.FormatBool(info.Reused), strconv.FormatBool(info.WasIdle)).Add(1)
					logger.Log("got connection event")
				},
				PutIdleConn: func(err error) {
					if err != nil {
						logger.Log("putidleconn error [error]", mhlog.ErrorKey, err)
					}
				},
				GotFirstResponseByte: func() {
					logger.Log("got first response byte event")
				},
				Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
					logger.Log("got 1xx continue event with code [code]", "code", code)
					return nil
				},
				DNSStart: func(info httptrace.DNSStartInfo) {
					logger.Log("dns start event for host [host]", "host", info.Host)
				},
				DNSDone: func(info httptrace.DNSDoneInfo) {
					storeEvent := EventInformation{
						Msg:  "dns resolved",
						Addr: info.Addrs[0].String(),
						Txid: r.Header["Transaction-Id"][0],
						Hook: "dnsdone",
					}
					if info.Err != nil {
						storeEvent = EventInformation{
							Msg:  info.Err.Error(),
							Addr: info.Addrs[0].String(),
							Txid: r.Header["Transaction-Id"][0],
							Hook: "dnsdone",
						}
						logger.Log("dns done event error [error] for txid [txid]", mhlog.ErrorKey, info.Err, "txid", r.Header["Transaction-Id"][0])
					} else {
						// Historic information shows IAM only returns a single address
						logger.Log("dns done event resolved address [addr] for txid [txid]", "addr", info.Addrs[0].String(), "txid", r.Header["Transaction-Id"][0])
					}
					storeEventInCache(storeEvent, logger)
				},
				ConnectStart: func(network, addr string) {
					txid := r.Header["Transaction-Id"][0]
					logger.Log("connect start event for network [net], address [addr] for txid [txid]", "net", network, "addr", addr, "txid", txid)
				},
				ConnectDone: func(network, addr string, err error) {
					if err != nil {
						storeEvent := EventInformation{
							Msg:  err.Error(),
							Addr: addr,
							Txid: r.Header["Transaction-Id"][0],
							Hook: "connectdone",
						}
						storeEventInCache(storeEvent, logger)
						logger.Log("connect done event error [error] for txid [txid]", mhlog.ErrorKey, err, "txid", r.Header["Transaction-Id"][0])
					} else {
						logger.Log("connect done event for network [net], address [addr]", "net", network, "addr", addr)
					}
				},
				TLSHandshakeStart: func() {
					logger.Log("tls handshake start event")
				},
				TLSHandshakeDone: func(connstate tls.ConnectionState, err error) {
					if err != nil {
						storeEvent := EventInformation{
							Msg:  err.Error(),
							Txid: r.Header["Transaction-Id"][0],
							Hook: "tlshandshakedone",
						}
						storeEventInCache(storeEvent, logger)
						logger.Log("tls handshake done event error [error]", mhlog.ErrorKey, err)
					} else {
						logger.Log("tls handshake done event for servername [sni] and complete [comp]", "comp", connstate.HandshakeComplete, "sni", connstate.ServerName)
					}
				},
				WroteHeaderField: func(key string, value []string) {
					if key == "Transaction-Id" || key == "Pragma" {
						str := key + ": "
						for _, v := range value {
							str = str + v + ","
						}
						logger.Log("wrote header field for [key]", "key", str)
					}
				},
				WroteHeaders: func() {
					logger.Log("wrote headers event")
				},
				WroteRequest: func(req httptrace.WroteRequestInfo) {
					if req.Err != nil {
						logger.Log("wrote request event error [error]", mhlog.ErrorKey, req.Err)
					}
				},
			}
			r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
			return next.RoundTrip(r)
		})
	}

	metricsRegisterer := prometheus.DefaultRegisterer

	metricsRegisterer.MustRegister(
		iamRequestCounter, iamRequestDuration, dnsLatencyVec, tlsLatencyVec, connPoolCounter)

	pooledTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(*config.HTTPTimeout) * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(*config.TLSTimeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   -1,
		DisableKeepAlives:     true,
	}

	// Define functions for the available httptrace.ClientTrace hook
	// functions that we want to instrument.
	trace := &promhttp.InstrumentTrace{
		DNSStart: func(t float64) {
			dnsLatencyVec.WithLabelValues("dns_start").Observe(t)
		},
		DNSDone: func(t float64) {
			dnsLatencyVec.WithLabelValues("dns_done").Observe(t)
		},
		TLSHandshakeStart: func(t float64) {
			tlsLatencyVec.WithLabelValues("tls_handshake_start").Observe(t)
		},
		TLSHandshakeDone: func(t float64) {
			tlsLatencyVec.WithLabelValues("tls_handshake_done").Observe(t)
		},
	}

	client := &http.Client{
		Transport: promhttp.InstrumentRoundTripperCounter(iamRequestCounter,
			connPoolInstrumenter(
				promhttp.InstrumentRoundTripperTrace(trace,
					promhttp.InstrumentRoundTripperDuration(iamRequestDuration,
						pooledTransport,
					),
				),
			),
		),
	}

	for {
		errCount := 0
		okCount := 0
		statuscodes := map[int]int{}

		for i := 0; i < 60; i++ {
			txid := fmt.Sprintf("actest-%s", uuid.NewUUID().String())
			resp, err := do(txid, logger, *config.Url, client)
			time.Sleep(time.Duration(*config.SleepTimeBetweenRequests) * time.Second)
			if err != nil {
				errCount++
				continue
			}
			resp.Body.Close()
			// Count the returned status codes
			_, ok := statuscodes[resp.StatusCode]
			if !ok {
				statuscodes[resp.StatusCode] = 1
			} else {
				statuscodes[resp.StatusCode]++
			}
			okCount++
		}

		//errPercent := (errCount * 100) / (errCount + okCount)
		//logger.Log("Pass = [okCount] Fail = [errCount] (Error Rate [rate])", "okCount", okCount, "errCount", errCount, "rate", errPercent)
		for code, count := range statuscodes {
			logger.Log("Status code [code] = [count]", "code", code, "count", count)
		}
	}

}

// ------------------------------------
// Private Helper Functions
// ------------------------------------

func readConfig() (Config, error) {
	config := Config{}
	config.Url = flag.String("Url", "https://iam.cloud.ibm.com/identity/introspect", "url - http endpoint to call")
	config.SleepTimeBetweenRequests = flag.Int("SleepTimeBetweenRequests", 5, "SleepTimeBetweenRequests - (secs)")
	config.HTTPTimeout = flag.Int("HTTPTimeout", 30, "HTTPTimeout - http timeout (secs)")
	config.TLSTimeout = flag.Int("TLSTimeout", 20, "TLSTimeout - tls handshake timeout (secs)")
	flag.Parse()
	return config, nil
}

func do(txid string, logger mhlog.Logger, url string, client *http.Client) (*http.Response, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		logger.Log("Problem creating NewRequest", mhlog.ErrorKey, err.Error())
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Transaction-Id", txid)
	req.Header.Set("Pragma", "akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-request-id")

	var resp *http.Response
	resp, err = client.Do(req)
	eventInterface, ok := acAddressCache.LoadAndDelete(txid)
	event := eventInterface.(EventInformation)
	if err != nil {
		logger.Log("actest error during introspect call to [addr] in [hook] for [txid]", "addr", event.Addr, "hook", event.Hook, "txid", event.Txid, mhlog.ErrorKey, event.Msg)
		if resp != nil {
			for k, v := range resp.Header {
				logger.Log("Response Header [key]: [value]", "key", k, "value", v)
			}
		}
		return nil, err
	}
	logger.Log("actest successful connect to [addr] (cache load [ok]) for transaction [txid]", "addr", event.Addr, "ok", ok, "txid", event.Txid)

	return resp, nil
}

func storeEventInCache(event EventInformation, logger mhlog.Logger) {
	logger.Log("storing event from [hook]", "hook", event.Hook)
	eventAlreadyStored, wasLoaded := acAddressCache.LoadOrStore(event.Txid, event)
	if wasLoaded {
		// Record the hooks the event was stored in, keeping latest event information
		hook := fmt.Sprintf("%s,%s", eventAlreadyStored.(EventInformation).Hook, event.Hook)
		event.Hook = hook
	}
	acAddressCache.Store(event.Txid, event)
}
