package anomaly

// detectCanaryAccess flags access to any canary/honeytoken entry.
// This is the highest-confidence indicator since canary entries have no
// legitimate reason for access — they are planted specifically for detection.
func (d *AnomalyDetector) detectCanaryAccess(event ToolCallEvent) *AnomalyAlert {
	if !event.IsCanary || event.Path == "" {
		return nil
	}
	return &AnomalyAlert{
		Type:        AlertCanaryAccess,
		Severity:    SeverityCritical,
		Description: "Honeytoken/canary entry accessed by agent " + event.Agent,
		Timestamp:   event.Timestamp,
		Agent:       event.Agent,
		Path:        event.Path,
		Tool:        event.Tool,
		RequestID:   event.RequestID,
	}
}

// detectOffHours flags access during configured off-hours (e.g., 10 PM - 6 AM).
func (d *AnomalyDetector) detectOffHours(event ToolCallEvent) *AnomalyAlert {
	if event.Path == "" {
		return nil
	}
	t := event.Timestamp
	currentHour := t.Hour()

	isOffHours := false
	if d.offHoursStart <= d.offHoursEnd {
		isOffHours = currentHour >= d.offHoursStart && currentHour < d.offHoursEnd
	} else {
		isOffHours = currentHour >= d.offHoursStart || currentHour < d.offHoursEnd
	}

	if !isOffHours {
		return nil
	}

	return &AnomalyAlert{
		Type:        AlertOffHours,
		Severity:    SeverityLow,
		Description: "Entry access during off-hours by agent " + event.Agent,
		Timestamp:   event.Timestamp,
		Agent:       event.Agent,
		Path:        event.Path,
		Tool:        event.Tool,
		RequestID:   event.RequestID,
	}
}

// detectSweep flags rapid access to many different unique paths within the
// sweep window (default: 10 unique paths in 60 seconds). This could indicate
// bulk exfiltration or reconnaissance.
func (d *AnomalyDetector) detectSweep(event ToolCallEvent) *AnomalyAlert {
	if event.Path == "" {
		return nil
	}

	cutoff := event.Timestamp.Add(-d.sweepWindow)
	seen := make(map[string]struct{})
	for _, e := range d.events {
		if e.Timestamp.Before(cutoff) {
			continue
		}
		if e.Path != "" {
			seen[e.Path] = struct{}{}
		}
	}

	if len(seen) >= d.sweepThreshold {
		return &AnomalyAlert{
			Type:        AlertSweep,
			Severity:    SeverityMedium,
			Description: "Sweep access detected: " + event.Agent + " accessed " + itoa(len(seen)) + " unique paths",
			Timestamp:   event.Timestamp,
			Agent:       event.Agent,
			Path:        event.Path,
			Tool:        event.Tool,
			RequestID:   event.RequestID,
		}
	}
	return nil
}

// detectRateAnomaly flags request rates exceeding the configured limit
// within the rate window (default: 30 requests in 60 seconds).
func (d *AnomalyDetector) detectRateAnomaly(event ToolCallEvent) *AnomalyAlert {
	cutoff := event.Timestamp.Add(-d.rateWindow)
	count := 0
	for _, e := range d.events {
		if e.Timestamp.Before(cutoff) {
			continue
		}
		if e.Agent == event.Agent {
			count++
		}
	}

	if count > d.rateLimit {
		return &AnomalyAlert{
			Type:        AlertRateAnomaly,
			Severity:    SeverityMedium,
			Description: "Rate anomaly: " + event.Agent + " made " + itoa(count) + " requests",
			Timestamp:   event.Timestamp,
			Agent:       event.Agent,
			Tool:        event.Tool,
			RequestID:   event.RequestID,
		}
	}
	return nil
}

// detectToolChain flags a tool-call chain where an agent reads a large field
// (likely notes containing injected content) then immediately invokes a
// command execution tool. This is the canonical prompt-injection exfiltration chain.
func (d *AnomalyDetector) detectToolChain(event ToolCallEvent) *AnomalyAlert {
	if event.Tool != "run_command" && event.Tool != "execute_with_secret" {
		return nil
	}
	cutoff := event.Timestamp.Add(-d.toolChainWindow)
	for i := len(d.events) - 1; i >= 0; i-- {
		e := d.events[i]
		if e.Timestamp.Before(cutoff) {
			break
		}
		if e.Agent != event.Agent {
			continue
		}
		if (e.Tool == "get_entry" || e.Tool == "get_entry_value") && e.FieldLength >= d.toolChainThreshold {
			return &AnomalyAlert{
				Type:     AlertToolChain,
				Severity: SeverityHigh,
				Description: "Tool-chain: agent " + event.Agent +
					" read a large field (" + itoa(e.FieldLength) + " bytes) then invoked " + event.Tool,
				Timestamp: event.Timestamp,
				Agent:     event.Agent,
				Path:      event.Path,
				Tool:      event.Tool,
				RequestID: event.RequestID,
			}
		}
	}
	return nil
}

// itoa is a fast integer to string conversion without importing strconv
// in the hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
