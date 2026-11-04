package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestActualPythonEventWireContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	core, err := filepath.Abs("../../../../libs/vulscan-core")
	if err != nil {
		t.Fatal(err)
	}
	code := `from core import ui_events
from core.progress import ProgressReporter
ui_events.start(verify=True,dynamic=True)
ui_events.emit("discovery.started",stage="analyze")
r={"route_key":"src/a.c:copy","finding":"vulnerable","cwe_id":120,"verification":{"agree":True},"attack_vector":"中文候选"}
ui_events.finding(r,stage="verify")
p=ProgressReporter("Detect",10)
p.report("same");p.report("same")
`
	cmd := exec.Command(python, "-c", code)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+core, "VULSCAN_JOB_ID=aabbccdd", "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python emitter: %v\n%s", err, output)
	}
	j := &Job{ID: "aabbccdd", Status: StatusRunning}
	j.Snapshot = newJobSnapshot(j, false)
	for _, line := range strings.Split(string(output), "\n") {
		j.addLog(line)
	}
	s := j.snapshotLocked()
	if len(s.Findings) != 1 || *s.Counts["retained"] != 1 || s.Findings["src/a.c:copy"].Title != "中文候选" {
		t.Fatalf("actual Python bytes did not project correctly: %+v", s)
	}
	if s.Stages["analyze"] == nil || *s.Stages["analyze"].Processed != 1 || *s.Stages["analyze"].Total != 10 {
		t.Fatal("retry double counted structured processing progress")
	}
}

func eventLine(id string, seq uint64, kind string, update func(*uiEvent)) string {
	e := uiEvent{Version: 1, JobID: id, Seq: seq, Type: kind, Time: time.Date(2026, 10, 25, 8, 0, int(seq), 0, time.UTC)}
	if update != nil {
		update(&e)
	}
	data, _ := json.Marshal(e)
	return uiEventPrefix + string(data)
}

func TestHumanLogsCannotBeAcceptedAsEventFrames(t *testing.T) {
	for _, wrap := range []func(string) string{
		func(frame string) string { return "[build] example output: " + frame },
		func(frame string) string { return frame + " trailing output" },
	} {
		j := &Job{ID: "frame-test", Status: StatusRunning}
		j.addLog(wrap(eventLine(j.ID, 1, "discovery.started", nil)))
		if j.Snapshot != nil && (j.Snapshot.Seq != 0 || j.Snapshot.DiscoveryKnown) {
			t.Fatal("ordinary log text changed structured scan state")
		}
	}
}

func TestFastStageResultsSurviveLaterStagesAndSnapshotRecovery(t *testing.T) {
	j := &Job{ID: "fast-stages", Status: StatusRunning, outDir: t.TempDir()}
	j.addLog(eventLine(j.ID, 1, "scan.started", func(e *uiEvent) { e.StageOrder = []string{"parse", "analyze", "verify"} }))
	j.addLog(eventLine(j.ID, 2, "stage.changed", func(e *uiEvent) { e.Stage, e.Status = "parse", "running" }))
	completed := eventLine(j.ID, 3, "stage.changed", func(e *uiEvent) {
		duration, cost, count := 0.08, 0.0, 12
		e.Stage, e.Status = "parse", "success"
		e.Duration, e.Cost, e.Processed, e.Total, e.Unit = &duration, &cost, &count, &count, "函数"
		e.Summary = map[string]any{"language": "javascript", "processing_level": "all"}
		e.Outputs = []string{"dataset.json"}
	})
	j.addLog(completed)
	j.addLog(completed)
	j.addLog(eventLine(j.ID, 4, "stage.changed", func(e *uiEvent) { e.Stage, e.Status = "analyze", "running" }))
	raw, err := os.ReadFile(filepath.Join(j.outDir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored jobSnapshot
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	st := restored.Stages["parse"]
	if restored.Stage != "analyze" || len(restored.StageOrder) != 3 || st == nil || st.Duration == nil || *st.Duration != 0.08 || st.Cost == nil || *st.Cost != 0 || *st.Processed != 12 || st.Summary["language"] != "javascript" || st.Outputs[0] != "dataset.json" || st.StartedAt == nil || st.FinishedAt == nil {
		t.Fatalf("completed fast stage lost its real result: %+v", st)
	}
}

func TestFailedReviewCanEnterDynamicTestingWithoutBecomingRetained(t *testing.T) {
	j := &Job{ID: "review-error", Status: StatusRunning}
	yes := true
	j.addLog(eventLine(j.ID, 1, "finding.upsert", func(e *uiEvent) {
		e.FindingID = "ini.js:decode"
		e.Finding = &uiFinding{ID: e.FindingID, ModelReview: "error", DynamicEligible: &yes, Dynamic: "pending"}
	}))
	update := eventLine(j.ID, 2, "validation.updated", func(e *uiEvent) {
		e.FindingID = "ini.js:decode"
		e.Finding = &uiFinding{ID: e.FindingID, Dynamic: "running", Attempt: 2}
	})
	j.addLog(update)
	j.addLog(update)
	s := j.snapshotLocked()
	for key, want := range map[string]int{"candidates": 1, "retained": 0, "excluded": 0, "review_incomplete": 1, "review_error": 1, "dynamic_eligible": 1} {
		if s.Counts[key] == nil || *s.Counts[key] != want {
			t.Errorf("%s: want %d, got %v", key, want, s.Counts[key])
		}
	}
	if s.Findings["ini.js:decode"].ModelReview != "error" || s.Counts["reproduced"] != nil {
		t.Fatal("queued test invented successful review or reproduction")
	}
}

func TestRestoreStageReportsUsesMatchingSavedDataWithoutOverwritingEvents(t *testing.T) {
	root := t.TempDir()
	j := &Job{ID: "history", Status: StatusDone, outDir: root}
	j.Snapshot = newJobSnapshot(j, false)
	j.Snapshot.Stages["parse"] = &uiStage{Status: "success"}
	j.Snapshot.Stages["enhance"] = &uiStage{Status: "success", Summary: map[string]any{"units_enhanced": 19}}
	j.Snapshot.Stages["verify"] = &uiStage{Status: "partial"}
	data := []byte(`{"step":"parse","status":"success","duration_seconds":0.08,"cost_usd":0,"summary":{"total_units":6,"language":"javascript"},"outputs":{"dataset_path":"/original/path/dataset.json"}}`)
	if err := os.WriteFile(filepath.Join(root, "parse.report.json"), data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "enhance.report.json"), []byte(`{"step":"enhance","status":"success","summary":{"units_enhanced":99}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "verify.report.json"), []byte(`{"step":"verify","status":"success","summary":{"confirmed_vulnerabilities":99}}`), 0640); err != nil {
		t.Fatal(err)
	}
	j.restoreStageReports()
	parse := j.Snapshot.Stages["parse"]
	if parse.Summary["language"] != "javascript" || parse.Duration == nil || *parse.Duration != 0.08 || len(parse.Outputs) != 1 || parse.Outputs[0] != "dataset.json" || parse.Cost == nil || *parse.Cost != 0 {
		t.Fatalf("saved stage result not restored: %+v", parse)
	}
	if j.Snapshot.Stages["enhance"].Summary["units_enhanced"] != 19 || j.Snapshot.Stages["verify"].Summary != nil {
		t.Fatal("saved file overwrote newer or mismatched event state")
	}
	after, err := os.ReadFile(filepath.Join(root, "parse.report.json"))
	if err != nil || string(after) != string(data) {
		t.Fatal("history projection changed the original report")
	}
	if j.Snapshot.DiscoveryKnown || len(j.Snapshot.Findings) != 0 {
		t.Fatal("code processing totals were converted into findings")
	}
}

func TestRestoreStageReportsRejectsSymlinksAndIncompleteCost(t *testing.T) {
	root := t.TempDir()
	j := &Job{ID: "history", Status: StatusDone, outDir: root, Snapshot: &jobSnapshot{Stages: map[string]*uiStage{"parse": {Status: "success"}, "analyze": {Status: "success"}, "enhance": {Status: "success"}}}}
	external := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(external, []byte(`{"step":"enhance","status":"success","summary":{"units_enhanced":99}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "enhance.report.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "parse.report.json"), []byte(`{"step":"parse","status":"success","cost_usd":0,"token_usage":{"cost_incomplete":true},"summary":{"total_units":6}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "analyze.report.json"), []byte(`{"step":`), 0640); err != nil {
		t.Fatal(err)
	}
	j.restoreStageReports()
	if j.Snapshot.Stages["enhance"].Summary != nil || j.Snapshot.Stages["parse"].Cost != nil || j.Snapshot.Stages["analyze"].Details == "" {
		t.Fatal("unsafe/missing history or incomplete cost looked valid")
	}
}

func TestFinalCoverageReconcilesRecoveredErrors(t *testing.T) {
	j := &Job{ID: "retry-test", Status: StatusRunning}
	j.addLog(eventLine(j.ID, 1, "error", func(e *uiEvent) { e.Stage = "analyze" }))
	j.addLog(eventLine(j.ID, 2, "stage.changed", func(e *uiEvent) { e.Stage = "analyze"; e.Status = "success" }))
	j.addLog(eventLine(j.ID, 3, "coverage.updated", func(e *uiEvent) { e.Status = "reported" }))
	if j.snapshotLocked().Partial {
		t.Fatal("recovered retry still presented as incomplete")
	}
	j.addLog(eventLine(j.ID, 4, "stage.changed", func(e *uiEvent) { e.Stage = "enhance"; e.Status = "partial" }))
	j.addLog(eventLine(j.ID, 5, "coverage.updated", func(e *uiEvent) { e.Status = "reported" }))
	if !j.snapshotLocked().Partial {
		t.Fatal("an actual partial stage was hidden by coverage reconciliation")
	}
	j.Snapshot.Coverage = "event_gap"
	j.addLog(eventLine(j.ID, 6, "coverage.updated", func(e *uiEvent) { e.Status = "reported" }))
	if j.snapshotLocked().Coverage != "event_gap" || !j.Snapshot.Partial {
		t.Fatal("transport gap was hidden by coverage reconciliation")
	}
}

func TestTerminalSnapshotHasNoPendingWorkAndPreservesResults(t *testing.T) {
	for _, status := range []string{StatusDone, StatusError, StatusTimeout, StatusCancelled} {
		t.Run(status, func(t *testing.T) {
			j := &Job{ID: "terminal-test", Status: status}
			j.Snapshot = newJobSnapshot(j, false)
			j.Snapshot.DiscoveryKnown = true
			j.Snapshot.Stages["queue"] = &uiStage{Status: "queued"}
			j.Snapshot.Stages["initialize"] = &uiStage{Status: "running"}
			j.Snapshot.Findings["pending"] = &uiFinding{ID: "pending", ModelReview: "pending", Dynamic: "pending"}
			j.Snapshot.Findings["running"] = &uiFinding{ID: "running", ModelReview: "retained", Dynamic: "running", Attempt: 2}
			j.Snapshot.Findings["finished"] = &uiFinding{ID: "finished", ModelReview: "retained", Dynamic: "reproduced", DynamicDetails: "saved result"}
			s := j.snapshotLocked()
			if s.Stages["queue"].Status != "interrupted" || s.Stages["initialize"].Status != "interrupted" || !s.Partial {
				t.Fatal("terminal snapshot retained an active stage")
			}
			if s.Findings["pending"].ModelReview != "interrupted" || s.Findings["pending"].Dynamic != "skipped" || s.Findings["running"].Dynamic != "interrupted" {
				t.Fatal("terminal finding still waiting or executing")
			}
			if *s.Counts["pending"] != 0 || *s.Counts["reproduced"] != 1 || s.Findings["finished"].DynamicDetails != "saved result" {
				t.Fatal("terminal projection erased a completed result or miscounted pending work")
			}
		})
	}
}

func TestSnapshotCountsIdentityOrderingAndIsolation(t *testing.T) {
	j := &Job{ID: "aabbccdd", Status: StatusRunning, StartedAt: time.Now(), outDir: t.TempDir()}
	j.Snapshot = newJobSnapshot(j, false)
	if j.Snapshot.Counts["candidates"] != nil {
		t.Fatal("unknown must not become zero")
	}
	stage := func(e *uiEvent) { e.Stage = "analyze"; e.Status = "running" }
	j.addLog(eventLine(j.ID, 1, "stage.changed", stage))
	j.addLog(eventLine(j.ID, 2, "discovery.started", nil))
	finding := func(state string) func(*uiEvent) {
		return func(e *uiEvent) {
			e.FindingID = "src/a.c:copy"
			e.Finding = &uiFinding{ID: e.FindingID, ModelReview: state, Title: "候选"}
		}
	}
	fourth := eventLine(j.ID, 4, "finding.upsert", finding("retained"))
	j.addLog(fourth) // gap: buffered, not lost or applied prematurely
	if len(j.Snapshot.Findings) != 0 {
		t.Fatal("out-of-order event applied before its predecessor")
	}
	third := eventLine(j.ID, 3, "finding.upsert", finding("pending"))
	j.addLog(third)
	j.addLog(third)
	j.addLog(fourth)
	if j.Snapshot.Seq != 4 || len(j.Snapshot.Findings) != 1 {
		t.Fatal("duplicate/reordered events changed cardinality")
	}
	j.addLog(eventLine("another-job", 5, "finding.upsert", finding("excluded")))
	if j.Snapshot.Seq != 4 {
		t.Fatal("cross-job event accepted")
	}
	j.addLog(eventLine(j.ID, 5, "validation.updated", func(e *uiEvent) {
		e.FindingID = "src/a.c:copy"
		e.Attempt = 2
		e.Finding = &uiFinding{ID: e.FindingID, Dynamic: "not_reproduced", Attempt: 2}
	}))
	j.addLog(eventLine(j.ID, 6, "validation.updated", func(e *uiEvent) {
		e.FindingID = "src/a.c:copy"
		e.Attempt = 1
		e.Finding = &uiFinding{ID: e.FindingID, Dynamic: "reproduced", Attempt: 1}
	}))
	s := j.snapshotLocked()
	if *s.Counts["candidates"] != 1 || *s.Counts["retained"] != 1 || *s.Counts["reproduced"] != 0 || *s.Counts["not_reproduced"] != 1 {
		t.Fatalf("incorrect independent projections: %+v", s.Counts)
	}
	if s.Findings["src/a.c:copy"].ModelReview != "retained" {
		t.Fatal("dynamic update erased model state")
	}
	data, err := os.ReadFile(filepath.Join(j.outDir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored jobSnapshot
	if err = json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	restored.projectCounts()
	if restored.Seq != s.Seq || *restored.Counts["candidates"] != 1 {
		t.Fatal("persisted snapshot differs from in-memory state")
	}
	j.addLog(eventLine(j.ID, 7, "finding.upsert", finding("excluded")))
	s = j.snapshotLocked()
	if *s.Counts["candidates"] != 1 || *s.Counts["excluded"] != 1 || *s.Counts["retained"] != 0 {
		t.Fatal("rejected candidate vanished or was double counted")
	}
}

func TestSnapshotZeroAndStageDenominators(t *testing.T) {
	j := &Job{ID: "zero", Status: StatusRunning}
	j.Snapshot = newJobSnapshot(j, false)
	j.addLog(eventLine(j.ID, 1, "discovery.started", nil))
	s := j.snapshotLocked()
	if s.Counts["candidates"] == nil || *s.Counts["candidates"] != 0 || s.Counts["reproduced"] != nil {
		t.Fatal("known zero and unproduced validation were conflated")
	}
	done, total := 94, 987
	elapsed, eta := 191.0, 1823.0
	j.addLog(eventLine(j.ID, 2, "progress.updated", func(e *uiEvent) {
		e.Stage = "enhance"
		e.Processed = &done
		e.Total = &total
		e.Elapsed = &elapsed
		e.ETA = &eta
		e.Message = "src/error_handler.c"
	}))
	j.addLog(eventLine(j.ID, 3, "stage.changed", func(e *uiEvent) { e.Stage = "analyze"; e.Status = "running" }))
	if s.Stages["analyze"].Total != nil || s.Stages["analyze"].ETA != nil || s.Stages["enhance"].Total == nil {
		t.Fatal("stage transition reused another stage's denominator/ETA")
	}
	if len(s.Findings) != 0 {
		t.Fatal("processed code units were counted as findings")
	}
}

func TestPendingAxesDoNotOverlapOrInventResults(t *testing.T) {
	j := &Job{ID: "pending", Status: StatusRunning}
	j.Snapshot = newJobSnapshot(j, false)
	j.addLog(eventLine(j.ID, 1, "finding.upsert", func(e *uiEvent) {
		e.FindingID = "a.c:copy"
		e.Finding = &uiFinding{ID: e.FindingID, ModelReview: "pending", Dynamic: "pending"}
	}))
	s := j.snapshotLocked()
	if *s.Counts["pending"] != 1 || s.Counts["retained"] != nil || s.Counts["excluded"] != nil || s.Counts["reproduced"] != nil {
		t.Fatal("pending model/dynamic states were added together or invented a zero result")
	}
	j.addLog(eventLine(j.ID, 2, "finding.upsert", func(e *uiEvent) {
		e.FindingID = "a.c:copy"
		e.Finding = &uiFinding{ID: e.FindingID, ModelReview: "excluded", Dynamic: "skipped"}
	}))
	s = j.snapshotLocked()
	if *s.Counts["pending"] != 0 || *s.Counts["retained"] != 0 || *s.Counts["excluded"] != 1 || *s.Counts["skipped"] != 1 || s.Counts["reproduced"] != nil {
		t.Fatal("known zero, skipped and missing execution results were conflated")
	}
}

func TestSnapshotRecoveryPreservesPartialAndPending(t *testing.T) {
	out := t.TempDir()
	id := "aabbccdd"
	dir := filepath.Join(out, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(jobMeta{ID: id, Repo: "fixture", Status: StatusTimeout, StartedAt: time.Now()})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0640); err != nil {
		t.Fatal(err)
	}
	j := &Job{ID: id, Repo: "fixture", Status: StatusTimeout, outDir: dir}
	j.Snapshot = newJobSnapshot(j, false)
	j.addLog(eventLine(id, 2, "finding.upsert", func(e *uiEvent) {
		e.FindingID = "f:c"
		e.Finding = &uiFinding{ID: e.FindingID, Dynamic: "environment_error"}
	}))
	j.addLog(eventLine(id, 1, "discovery.started", nil))
	s := &Server{outDir: out, mgr: newManager(out)}
	s.recoverJobs()
	restored, ok := s.mgr.get(id)
	if !ok {
		t.Fatal("job not restored")
	}
	got := restored.snapshotLocked()
	if got.Status != StatusTimeout || !got.Partial || got.Legacy || len(got.Findings) != 1 || *got.Counts["environment_error"] != 1 {
		t.Fatalf("incorrect recovery: %+v", got)
	}
}

func TestConcurrentSnapshotReadsAndOutOfOrderWriters(t *testing.T) {
	j := &Job{ID: "aabbccdd", Status: StatusRunning, StartedAt: time.Now(), outDir: t.TempDir()}
	j.Snapshot = newJobSnapshot(j, false)
	s := &Server{mgr: newManager(t.TempDir())}
	s.mgr.add(j)
	var writers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for n := worker + 1; n <= 80; n += 4 {
				line := eventLine(j.ID, uint64(n), "finding.upsert", func(e *uiEvent) {
					e.FindingID = fmt.Sprintf("src/a.c:copy_%d", n)
					e.Finding = &uiFinding{ID: e.FindingID, ModelReview: "pending"}
				})
				j.addLog(line)
				j.addLog(line)
			}
		}(worker)
	}
	for n := 0; n < 40; n++ {
		r := httptest.NewRequest("GET", "/scan/"+j.ID+"/snapshot", nil)
		r.SetPathValue("id", j.ID)
		w := httptest.NewRecorder()
		s.handleSnapshot(w, r)
		var snapshot jobSnapshot
		if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || w.Code != 200 {
			t.Fatalf("concurrent snapshot response: %d %v", w.Code, err)
		}
		if len(snapshot.Findings) > 80 {
			t.Fatal("duplicate writer inflated candidate count")
		}
	}
	writers.Wait()
	got := j.snapshotLocked()
	if got.Seq != 80 || len(got.Pending) != 0 || len(got.Findings) != 80 || *got.Counts["pending"] != 80 {
		t.Fatal("concurrent delivery lost or duplicated state")
	}
}
