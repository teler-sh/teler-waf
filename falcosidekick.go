// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"bytes"
	"time"

	"encoding/json"
	"net/http"

	"github.com/daniel-hutao/spinlock"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/slices"
)

// falcoEvent represents a Falco event structure.
// It is used for marshaling Falco events to JSON format.
type falcoEvent struct {
	Output       string `json:"output"`
	Priority     string `json:"priority"`
	Rule         string `json:"rule"`
	Time         string `json:"time"`
	OutputFields struct {
		Caller         string `json:"teler.caller"`
		ID             string `json:"teler.id"`
		Threat         string `json:"teler.threat"`
		ListenAddr     string `json:"teler.listen_addr"`
		RequestBody    string `json:"request.body"`
		RequestHeaders string `json:"request.headers"`
		RequestIPAddr  string `json:"request.ip_addr"`
		RequestMethod  string `json:"request.method"`
		RequestPath    string `json:"request.path"`
	} `json:"output_fields"`
}

// falcoSidekick represents a data structure for managing
// a collection of Falco events and a SpinLock for concurrent
// access control.
type falcoSidekick struct {
	events []*falcoEvent
	sl     spinlock.SpinLock
}

// checkFalcoEvents periodically checks for pending Falco events and
// sends them to a FalcoSidekick instance.
//
// If the FalcoSidekick URL is configured. It runs as a background goroutine.
func (t *Teler) checkFalcoEvents() {
	// If the FalcoSidekick URL is not configured, do nothing.
	if t.opt.FalcoSidekickURL == "" {
		return
	}

	// Initialize ticker
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	// Check for pending Falco events every 5 seconds.
	for range ticker.C {
		// Lock the FalcoSidekick event
		t.falcoSidekick.sl.Lock()

		// Get the count of pending Falco events.
		c := len(t.falcoSidekick.events)
		if c > 0 {
			// Send pending Falco events to FalcoSidekick.
			t.sendFalcoEvents()
		}

		// Unlock the FalcoSidekick event
		t.falcoSidekick.sl.Unlock()
	}
}

// sendFalcoEvents sends pending Falco events to a FalcoSidekick instance.
// It uses a goroutine pool to parallelize the sending of events.
func (t *Teler) sendFalcoEvents() {
	// Lock the FalcoSidekick event slice to prevent concurrent access.
	t.falcoSidekick.sl.Lock()
	defer t.falcoSidekick.sl.Unlock()

	// Get the number of pending Falco events.
	i := len(t.falcoSidekick.events)

	// Initialize worker number
	var w int

	// Define worker number logic
	w = i / 2
	if w == 0 {
		w = 1
	}

	// Create a goroutine pool with a maximum number of goroutines (workers)
	// equal to half the number of pending events.
	p := pool.New().WithMaxGoroutines(w)

	// Iterate over the pending Falco events.
	for _, event := range t.falcoSidekick.events {
		e := event
		p.Go(func() {
			// Marshal the Falco event to JSON format.
			payload, err := json.Marshal(e)
			if err != nil {
				// Handle JSON marshaling error by logging an error message.
				t.error(zapcore.ErrorLevel, err.Error())
			}

			// Send a POST request to the FalcoSidekick instance with the JSON payload.
			resp, err := http.Post(t.opt.FalcoSidekickURL, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				// Handle HTTP POST request error by logging an error message.
				t.error(zapcore.ErrorLevel, err.Error())
			} else {
				defer resp.Body.Close()
			}
		})
	}

	// Wait for all goroutines in the pool to complete.
	p.Wait()

	// Remove sent Falco events from the pending events slice.
	t.falcoSidekick.events = slices.Delete(t.falcoSidekick.events, 0, i)
}
