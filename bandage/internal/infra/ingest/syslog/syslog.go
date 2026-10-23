// Package syslog is the syslog ingest driver (go-syslog.v2, flux parity):
// tcp, udp or unixgram listeners with automatic format detection, pure transport.
package syslog

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	gsyslog "gopkg.in/mcuadros/go-syslog.v2"
	gformat "gopkg.in/mcuadros/go-syslog.v2/format"
)

// partsChannelBuffer absorbs brief handler backpressure.
const partsChannelBuffer = 256

// Source receives syslog messages and forwards each raw message line on
// out. One worker preserves message order.
type Source struct {
	network string
	addr    string
	out     chan<- string
	logger  zerolog.Logger

	srv      *gsyslog.Server
	parts    gsyslog.LogPartsChannel
	stopped  atomic.Bool
	finished chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
}

// New returns a syslog source for the given network ("tcp", "udp" or "unixgram")
// and listen address; Start binds the listener.
func New(network, addr string, out chan<- string, logger zerolog.Logger) *Source {
	return &Source{
		network:  network,
		addr:     addr,
		out:      out,
		logger:   logger,
		parts:    make(gsyslog.LogPartsChannel, partsChannelBuffer),
		finished: make(chan struct{}),
	}
}

// Start binds the listener and starts the forwarding worker.
func (s *Source) Start() error {
	handler := gsyslog.NewChannelHandler(s.parts)
	s.srv = gsyslog.NewServer()
	s.srv.SetFormat(gsyslog.Automatic)
	s.srv.SetHandler(handler)

	var err error
	switch s.network {
	case "tcp":
		err = s.srv.ListenTCP(s.addr)
	case "udp":
		err = s.srv.ListenUDP(s.addr)
	case "unixgram":
		err = s.srv.ListenUnixgram(s.addr)
	default:
		return fmt.Errorf("syslog: unknown network %q", s.network)
	}
	if err != nil {
		return fmt.Errorf("syslog: listen %s %s: %w", s.network, s.addr, err)
	}
	if err := s.srv.Boot(); err != nil {
		return fmt.Errorf("syslog: boot %s %s: %w", s.network, s.addr, err)
	}
	s.logger.Info().Str("network", s.network).Str("addr", s.addr).Msg("syslog ingest started")

	s.wg.Add(1)
	go s.run()
	return nil
}

// run forwards raw message lines in arrival order; after Shutdown it keeps
// draining (discarding) until every producer winds down, so none block on its handler.
func (s *Source) run() {
	defer s.wg.Done()
	for {
		select {
		case part := <-s.parts:
			if s.stopped.Load() {
				continue
			}
			s.out <- extractLine(part)
		case <-s.finished:
			return
		}
	}
}

// extractLine pulls the raw message text out of the parsed syslog parts
// (flux parity: "content", falling back to "message").
func extractLine(part gformat.LogParts) string {
	if part == nil {
		return ""
	}
	if line, ok := part["content"].(string); ok {
		return line
	}
	if line, ok := part["message"].(string); ok {
		return line
	}
	// Unrecognized parts become an empty line: the parser drops and counts it.
	return ""
}

// Shutdown stops the listener and drains the pipeline. It is idempotent.
func (s *Source) Shutdown() error {
	var err error
	s.once.Do(func() {
		s.stopped.Store(true)
		if s.srv != nil {
			err = s.srv.Kill()
			// Wait for producers while run() drains; then run() exits.
			go func() {
				s.srv.Wait()
				close(s.finished)
			}()
			s.wg.Wait()
		}
	})
	return err
}
