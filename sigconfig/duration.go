// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sigconfig

import (
	"encoding/json"
	"fmt"
	"time"
)

// A Duration is a time.Duration that marshals as a Go duration string, such
// as "5m" or "1h30m". Only the string form is accepted.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("sigconfig: duration must be a string such as \"5m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("sigconfig: %w", err)
	}
	*d = Duration(v)
	return nil
}
