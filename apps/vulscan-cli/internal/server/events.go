package server

// Presentation state only. Neither this reducer nor its counters participate in
// detection, verdict selection, retries, cancellation or Docker cleanup.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const uiEventPrefix = "@vulscan-event "

type uiFinding struct {
	ID             string `json:"finding_id"`
	ReportID       string `json:"report_id,omitempty"`
	Title          string `json:"title,omitempty"`
	Severity       string `json:"severity,omitempty"`
	File           string `json:"file,omitempty"`
	Function       string `json:"function,omitempty"`
	CWE            string `json:"cwe,omitempty"`
	CWEName        string `json:"cwe_name,omitempty"`
	Verdict        string `json:"verdict,omitempty"`
	ModelReview    string `json:"model_review,omitempty"`
	ReviewDetails  string `json:"review_details,omitempty"`
	Description    string `json:"description,omitempty"`
	Dynamic        string `json:"dynamic,omitempty"`
	DynamicDetails string `json:"dynamic_details,omitempty"`
	FailurePhase   string `json:"failure_phase,omitempty"`
	Attempt        int    `json:"attempt,omitempty"`
	FirstSeq       uint64 `json:"first_seq"`
}

type uiEvent struct {
	Source    string     `json:"source,omitempty"`
	SourceSeq uint64     `json:"source_seq,omitempty"`
	Version   int        `json:"version"`
	JobID     string     `json:"job_id"`
	Seq       uint64     `json:"seq"`
	Type      string     `json:"type"`
	Time      time.Time  `json:"time"`
	Stage     string     `json:"stage,omitempty"`
	Phase     string     `json:"phase,omitempty"`
	Status    string     `json:"status,omitempty"`
	FindingID string     `json:"finding_id,omitempty"`
	Attempt   int        `json:"attempt,omitempty"`
	Finding   *uiFinding `json:"finding,omitempty"`
	Processed *int       `json:"processed,omitempty"`
	Total     *int       `json:"total,omitempty"`
	Unit      string     `json:"unit,omitempty"`
	Elapsed   *float64   `json:"elapsed_seconds,omitempty"`
	ETA       *float64   `json:"eta_seconds,omitempty"`
	Duration  *float64   `json:"duration_seconds,omitempty"`
	Message   string     `json:"message,omitempty"`
	Details   string     `json:"details,omitempty"`
}

type uiStage struct {
	Status    string   `json:"status"`
	Processed *int     `json:"processed"`
	Total     *int     `json:"total"`
	Unit      string   `json:"unit"`
	Elapsed   *float64 `json:"elapsed_seconds"`
	ETA       *float64 `json:"eta_seconds"`
	Duration  *float64 `json:"duration_seconds"`
	Activity  string   `json:"activity"`
}

type jobSnapshot struct {
	Artifacts        map[string]bool       `json:"artifacts"`
	ActivitySeq      uint64                `json:"activity_seq"`
	CoverageDetails  string                `json:"coverage_details,omitempty"`
	Version          int                   `json:"version"`
	JobID            string                `json:"job_id"`
	Seq              uint64                `json:"seq"`
	Revision         uint64                `json:"revision"`
	Status           string                `json:"status"`
	Repo             string                `json:"repo"`
	Branch           string                `json:"branch,omitempty"`
	Commit           string                `json:"commit,omitempty"`
	StartedAt        time.Time             `json:"started_at"`
	FinishedAt       *time.Time            `json:"finished_at,omitempty"`
	UpdatedAt        time.Time             `json:"updated_at"`
	Legacy           bool                  `json:"legacy"`
	DiscoveryKnown   bool                  `json:"discovery_known"`
	Partial          bool                  `json:"partial"`
	Coverage         string                `json:"coverage"`
	Stage            string                `json:"stage"`
	Stages           map[string]*uiStage   `json:"stages"`
	Findings         map[string]*uiFinding `json:"findings"`
	Counts           map[string]*int       `json:"counts"`
	Activity         []uiEvent             `json:"activity"`
	ActivityOmitted  int                   `json:"activity_omitted"`
	Pending          map[uint64]uiEvent    `json:"pending,omitempty"`
	PersistenceError string                `json:"persistence_error,omitempty"`
}

func newJobSnapshot(j *Job, legacy bool) *jobSnapshot {
	return &jobSnapshot{Version: 1, JobID: j.ID, Status: j.Status, Repo: j.Repo,
		StartedAt: j.StartedAt, UpdatedAt: j.StartedAt, Legacy: legacy, Coverage: "unknown",
		Stages: map[string]*uiStage{}, Findings: map[string]*uiFinding{},
		Counts: map[string]*int{}, Pending: map[uint64]uiEvent{}, Activity: []uiEvent{}}
}

func (j *Job) snapshotLocked() *jobSnapshot {
	if j.Snapshot == nil {
		j.Snapshot = newJobSnapshot(j, true)
	}
	s := j.Snapshot
	if s.Status != j.Status {
		s.Status = j.Status
		s.Revision++
		s.UpdatedAt = time.Now().UTC()
	}
	// A completed invocation alone does not prove complete code coverage.
	if !scanActive(j.Status) && j.Status != StatusDone {
		s.Partial = true
	}
	s.projectCounts()
	s.Artifacts = map[string]bool{"report": j.ReportPath != "", "summary": j.SummaryPath != "", "disclosures": len(j.DisclosurePaths) > 0}
	return s
}

func (s *jobSnapshot) projectCounts() {
	s.Counts = map[string]*int{}
	for _, k := range []string{"candidates", "retained", "excluded", "pending", "reproduced", "not_reproduced", "environment_error", "skipped"} {
		s.Counts[k] = nil
	}
	if !s.DiscoveryKnown {
		return
	}
	n := len(s.Findings)
	s.Counts["candidates"] = &n
	reviewKnown, reviewResultKnown, dynamicKnown, dynamicResultKnown := false, false, false, false
	reviewValues, dynamicValues := map[string]int{}, map[string]int{}
	for _, f := range s.Findings {
		if f.ModelReview == "pending" || f.ModelReview == "not_requested" || f.ModelReview == "retained" || f.ModelReview == "excluded" || f.ModelReview == "error" || f.ModelReview == "inconclusive" {
			reviewKnown = true
			reviewValues[f.ModelReview]++
			if f.ModelReview == "retained" || f.ModelReview == "excluded" || f.ModelReview == "error" || f.ModelReview == "inconclusive" {
				reviewResultKnown = true
			}
		}
		if f.Dynamic == "pending" || f.Dynamic == "running" || f.Dynamic == "skipped" || f.Dynamic == "reproduced" || f.Dynamic == "not_reproduced" || f.Dynamic == "blocked" || f.Dynamic == "error" || f.Dynamic == "environment_error" || f.Dynamic == "inconclusive" {
			dynamicKnown = true
			dynamicValues[f.Dynamic]++
			if f.Dynamic == "reproduced" || f.Dynamic == "not_reproduced" || f.Dynamic == "blocked" || f.Dynamic == "error" || f.Dynamic == "environment_error" || f.Dynamic == "inconclusive" {
				dynamicResultKnown = true
			}
		}
	}
	for _, k := range []string{"retained", "excluded", "pending"} {
		if reviewResultKnown || (k == "pending" && reviewKnown) {
			v := reviewValues[k]
			s.Counts[k] = &v
		}
	}
	for _, k := range []string{"reproduced", "not_reproduced", "environment_error", "skipped"} {
		if dynamicResultKnown || (k == "skipped" && dynamicKnown) {
			v := dynamicValues[k]
			s.Counts[k] = &v
		}
	}
}

func (j *Job) acceptUIEventLocked(line string) {
	start := strings.Index(line, uiEventPrefix)
	if start < 0 {
		return
	}
	var e uiEvent
	if len(line) > 128<<10 || json.NewDecoder(strings.NewReader(line[start+len(uiEventPrefix):])).Decode(&e) != nil ||
		e.Version != 1 || e.JobID != j.ID || e.Seq == 0 || e.Time.IsZero() {
		return
	}
	if e.Processed != nil && *e.Processed < 0 || e.Total != nil && *e.Total < 0 {
		return
	}
	s := j.snapshotLocked()
	if e.Seq <= s.Seq {
		return
	}
	if s.Pending == nil {
		s.Pending = map[uint64]uiEvent{}
	}
	// Bounded reorder buffer. A broken producer is visible as incomplete,
	// never accepted as a complete/reconciled result set.
	if e.Seq > s.Seq+1024 {
		s.Partial = true
		s.Coverage = "event_gap"
		return
	}
	s.Pending[e.Seq] = e
	for {
		next, ok := s.Pending[s.Seq+1]
		if !ok {
			break
		}
		delete(s.Pending, s.Seq+1)
		s.reduce(next)
	}
	j.persistSnapshotLocked()
}

func (s *jobSnapshot) reduce(e uiEvent) {
	s.Seq, s.UpdatedAt = e.Seq, e.Time
	s.Revision++
	s.Legacy = false
	switch e.Type {
	case "discovery.started":
		s.DiscoveryKnown = true
	case "stage.changed", "progress.updated":
		st := s.Stages[e.Stage]
		if st == nil {
			st = &uiStage{}
			s.Stages[e.Stage] = st
		}
		if e.Type == "stage.changed" {
			if !(st.Status == "error" && e.Status == "skipped") {
				st.Status = e.Status
			}
			st.Duration = e.Duration
		}
		if e.Processed != nil {
			st.Processed = e.Processed
		}
		if e.Total != nil {
			st.Total = e.Total
		}
		if e.Unit != "" {
			st.Unit = e.Unit
		}
		if e.Elapsed != nil {
			st.Elapsed = e.Elapsed
		}
		if e.ETA != nil {
			st.ETA = e.ETA
		}
		st.Activity = e.Message
		s.Stage = e.Stage
		if e.Status == "partial" || e.Status == "error" || e.Status == "interrupted" {
			s.Partial = true
			s.Coverage = "incomplete"
		}
	case "finding.upsert", "validation.updated":
		if e.Finding == nil || e.FindingID == "" || e.Finding.ID != e.FindingID {
			break
		}
		f := s.Findings[e.FindingID]
		if f == nil {
			f = &uiFinding{ID: e.FindingID, FirstSeq: e.Seq}
			s.Findings[e.FindingID] = f
		}
		if e.Attempt > 0 && e.Attempt < f.Attempt {
			break
		}
		mergeFinding(f, e.Finding)
		s.DiscoveryKnown = true
	case "activity":
		if e.Stage == s.Stage && e.Status == "running" && s.Stages[e.Stage] != nil {
			s.Stages[e.Stage].Activity = e.Message
		}
	case "error":
		s.Partial = true
		s.Coverage = "incomplete"
	case "coverage.updated":
		s.Coverage = e.Status
		s.CoverageDetails = e.Message
	}
	// Progress is sampled into the stage snapshot, not thousands of activity
	// rows. The raw event is still retained in the original log stream.
	if e.Type != "progress.updated" {
		e.Source = "scanner"
		e.SourceSeq = e.Seq
		s.appendActivity(e)
	}
}

func (s *jobSnapshot) appendActivity(e uiEvent) {
	s.ActivitySeq++
	e.Seq = s.ActivitySeq
	s.Activity = append(s.Activity, e)
	if len(s.Activity) > 1000 {
		s.Activity = s.Activity[1:]
		s.ActivityOmitted++
	}
}

func (j *Job) runnerEventLocked(stage, status, message, details string, terminal bool) {
	s := j.snapshotLocked()
	now := time.Now().UTC()
	s.Revision++
	s.UpdatedAt = now
	if status == "partial" || status == "error" || status == "interrupted" {
		s.Partial = true
	}
	kind := "stage.changed"
	if terminal {
		kind = "task.terminal"
	} else {
		if s.Stages[stage] == nil {
			s.Stages[stage] = &uiStage{}
		}
		s.Stages[stage].Status = status
		s.Stages[stage].Activity = message
		s.Stage = stage
	}
	s.appendActivity(uiEvent{Version: 1, JobID: j.ID, Type: kind, Time: now, Stage: stage, Source: "runner", Status: status, Message: message, Details: details})
	j.persistSnapshotLocked()
}

func (j *Job) runnerEvent(stage, status, message, details string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.runnerEventLocked(stage, status, message, details, false)
}

func mergeFinding(dst, src *uiFinding) {
	if src.Dynamic != "" && src.Dynamic != "error" && src.Dynamic != "environment_error" {
		dst.FailurePhase = ""
	}
	if src.Dynamic == "running" && src.Attempt > dst.Attempt {
		dst.DynamicDetails = ""
	}
	// Explicit field merge: a validation event cannot erase model evidence or
	// the stable first-seen order. Empty fields represent absent information.
	for _, p := range [][2]*string{
		{&dst.ReportID, &src.ReportID}, {&dst.Title, &src.Title}, {&dst.Severity, &src.Severity},
		{&dst.File, &src.File}, {&dst.Function, &src.Function}, {&dst.CWE, &src.CWE}, {&dst.CWEName, &src.CWEName},
		{&dst.Verdict, &src.Verdict}, {&dst.ModelReview, &src.ModelReview}, {&dst.ReviewDetails, &src.ReviewDetails},
		{&dst.Description, &src.Description}, {&dst.Dynamic, &src.Dynamic}, {&dst.DynamicDetails, &src.DynamicDetails},
		{&dst.FailurePhase, &src.FailurePhase},
	} {
		if *p[1] != "" {
			*p[0] = *p[1]
		}
	}
	if src.Attempt > 0 {
		dst.Attempt = src.Attempt
	}
}

func (j *Job) persistSnapshotLocked() {
	if j.outDir == "" || j.Snapshot == nil {
		return
	}
	s := j.snapshotLocked()
	data, err := json.Marshal(s)
	if err == nil {
		path := filepath.Join(j.outDir, "snapshot.json")
		err = os.WriteFile(path+".tmp", data, 0640)
		if err == nil {
			err = os.Rename(path+".tmp", path)
		}
	}
	if err != nil {
		s.PersistenceError = "状态保存失败，请检查任务目录权限和磁盘空间"
	}
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	j, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	j.mu.Lock()
	data, err := json.Marshal(j.snapshotLocked())
	j.mu.Unlock()
	if err != nil {
		http.Error(w, "任务状态编码失败", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleSnapshotEvents(w http.ResponseWriter, r *http.Request) {
	j, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var sent []byte
	for {
		j.mu.Lock()
		data, err := json.Marshal(j.snapshotLocked())
		status := j.Status
		j.mu.Unlock()
		if err != nil {
			return
		}
		if !bytes.Equal(data, sent) {
			// Authoritative replacement on every reconnect; no additive counters.
			if _, err = fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data); err != nil {
				return
			}
			sent = data
			f.Flush()
		}
		if !scanActive(status) {
			fmt.Fprintf(w, "event: done\ndata: %s\n\n", status)
			f.Flush()
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) handleLogDownload(w http.ResponseWriter, r *http.Request) {
	j, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	j.mu.Lock()
	data := strings.Join(j.LogBuf, "\n")
	j.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="scan-logs.txt"`)
	_, _ = fmt.Fprintln(w, data)
}
