package db

import (
	"fmt"
	"testing"
	"time"
)

func TestTaskProgressCounters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	taskID := fmt.Sprintf("progress-test-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = d.DeleteTaskProgress(taskID) })

	// The first round establishes the baseline and does not immediately count idle.
	if idle, err := d.RecordTaskProgress(taskID, 1, 10, 5, 20); err != nil || idle != 0 {
		t.Fatalf("round1 idle=%d err=%v want 0", idle, err)
	}
	// Consecutive zero growth -> 1, 2.
	if idle, _ := d.RecordTaskProgress(taskID, 2, 10, 5, 20); idle != 1 {
		t.Fatalf("round2 idle=%d want 1", idle)
	}
	if idle, _ := d.RecordTaskProgress(taskID, 3, 10, 5, 20); idle != 2 {
		t.Fatalf("round3 idle=%d want 2", idle)
	}
	// A late old round must not be counted again.
	if idle, _ := d.RecordTaskProgress(taskID, 2, 10, 5, 20); idle != 2 {
		t.Fatalf("duplicate round idle=%d want 2", idle)
	}
	// Any counter growth -> idle resets to zero.
	if idle, _ := d.RecordTaskProgress(taskID, 4, 11, 5, 20); idle != 0 {
		t.Fatalf("progress round idle=%d want 0", idle)
	}
	p, err := d.GetTaskProgress(taskID)
	if err != nil || p == nil || p.RoundNo != 4 || p.FactCount != 11 {
		t.Fatalf("get progress=%+v err=%v", p, err)
	}
	// Reset only clears idle and keeps the counter baseline.
	if _, err := d.RecordTaskProgress(taskID, 5, 11, 5, 20); err != nil {
		t.Fatalf("round5: %v", err)
	}
	if err := d.ResetTaskProgress(taskID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if p, _ := d.GetTaskProgress(taskID); p == nil || p.IdleRounds != 0 || p.FactCount != 11 {
		t.Fatalf("after reset progress=%+v", p)
	}
	// It does not exist after deletion.
	_ = d.DeleteTaskProgress(taskID)
	if p, _ := d.GetTaskProgress(taskID); p != nil {
		t.Fatalf("progress should be deleted, got %+v", p)
	}
}

func TestCountExplorationProgress(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	facts, findings, err := d.CountExplorationProgress(-12345)
	if err != nil || facts != 0 || findings != 0 {
		t.Fatalf("empty exploration facts=%d findings=%d err=%v", facts, findings, err)
	}
}
