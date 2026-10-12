package store

import (
	"context"
	"path/filepath"
	"testing"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClaimRecoverAndCancel(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created := &analysisv1.Analysis{
		Id: "job-1", State: analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED,
		Filename: "sample.exe", SampleSha256: string(make([]byte, 64)), SampleSize: 10,
		Options: &analysisv1.AnalysisOptions{}, CreatedAt: timestamppb.Now(),
	}
	if _, err := store.Create(ctx, created, "once"); err != nil {
		t.Fatal(err)
	}
	duplicate := proto.Clone(created).(*analysisv1.Analysis)
	duplicate.Id = "job-2"
	got, err := store.Create(ctx, duplicate, "once")
	if err != nil || got.Id != created.Id {
		t.Fatalf("idempotent Create() = %v, %v", got, err)
	}
	running, err := store.ClaimNext(ctx)
	if err != nil || running.State != analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING {
		t.Fatalf("ClaimNext() = %v, %v", running, err)
	}
	if err := store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Get(ctx, created.Id)
	if err != nil || recovered.State != analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED {
		t.Fatalf("Recover() state = %v, %v", recovered.State, err)
	}
	cancelled, err := store.Cancel(ctx, created.Id)
	if err != nil || cancelled.State != analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED {
		t.Fatalf("Cancel() = %v, %v", cancelled, err)
	}
}
