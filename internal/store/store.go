package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

type Artifact struct {
	ID          string
	AnalysisID  string
	Kind        string
	Name        string
	SHA256      string
	Size        int64
	ContentType string
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  state INTEGER NOT NULL,
  filename TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  sample_size INTEGER NOT NULL,
  options_json BLOB NOT NULL,
  idempotency_key TEXT UNIQUE,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  report_sha256 TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS analyses_state_created ON analyses(state, created_at);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  content_type TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS artifacts_analysis ON artifacts(analysis_id);
`)
	return err
}

func (s *Store) Create(ctx context.Context, a *analysisv1.Analysis, idempotencyKey string) (*analysisv1.Analysis, error) {
	options, err := protojson.Marshal(a.Options)
	if err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO analyses
	  (id,state,filename,sample_sha256,sample_size,options_json,idempotency_key,created_at)
	  VALUES(?,?,?,?,?,?,NULLIF(?,''),?)`,
		a.Id, a.State, a.Filename, a.SampleSha256, a.SampleSize, options, idempotencyKey, a.CreatedAt.AsTime().UTC().Format(time.RFC3339Nano))
	if err != nil {
		if idempotencyKey != "" {
			var id string
			if lookupErr := s.db.QueryRowContext(ctx, `SELECT id FROM analyses WHERE idempotency_key=?`, idempotencyKey).Scan(&id); lookupErr == nil {
				return s.Get(ctx, id)
			}
		}
		return nil, err
	}
	return a, nil
}

func (s *Store) Get(ctx context.Context, id string) (*analysisv1.Analysis, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,state,filename,sample_sha256,sample_size,options_json,
	  created_at,COALESCE(started_at,''),COALESCE(finished_at,''),error_code,error_message
	  FROM analyses WHERE id=?`, id)
	return scanAnalysis(row)
}

func (s *Store) List(ctx context.Context, limit int, after string) ([]*analysisv1.Analysis, string, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,state,filename,sample_sha256,sample_size,options_json,
	  created_at,COALESCE(started_at,''),COALESCE(finished_at,''),error_code,error_message
	  FROM analyses WHERE created_at < COALESCE(NULLIF(?,''),'9999-12-31T23:59:59Z')
	  ORDER BY created_at DESC LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []*analysisv1.Analysis
	for rows.Next() {
		item, err := scanAnalysis(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, item)
	}
	var next string
	if len(out) > limit {
		next = out[limit-1].CreatedAt.AsTime().UTC().Format(time.RFC3339Nano)
		out = out[:limit]
	}
	return out, next, rows.Err()
}

func (s *Store) ClaimNext(ctx context.Context) (*analysisv1.Analysis, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM analyses WHERE state=? ORDER BY created_at LIMIT 1`,
		analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `UPDATE analyses SET state=?,started_at=? WHERE id=? AND state=?`,
		analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING, now, id, analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Store) Finish(ctx context.Context, id string, state analysisv1.AnalysisState, reportHash, code, message string) error {
	if state != analysisv1.AnalysisState_ANALYSIS_STATE_SUCCEEDED &&
		state != analysisv1.AnalysisState_ANALYSIS_STATE_FAILED &&
		state != analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED {
		return fmt.Errorf("invalid terminal state %s", state)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE analyses SET state=?,finished_at=?,report_sha256=?,error_code=?,error_message=?
	  WHERE id=? AND state=?`, state, time.Now().UTC().Format(time.RFC3339Nano), reportHash, code, message, id,
		analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Cancel(ctx context.Context, id string) (*analysisv1.Analysis, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE analyses SET state=?,finished_at=? WHERE id=? AND state IN (?,?)`,
		analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED, now, id,
		analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED, analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Store) Recover(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE analyses SET state=?,started_at=NULL,error_code='',error_message=''
	  WHERE state=?`, analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED, analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING)
	return err
}

func (s *Store) QueueDepth(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM analyses WHERE state=?`,
		analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED).Scan(&count)
	return count, err
}

func (s *Store) ReportHash(ctx context.Context, id string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT report_sha256 FROM analyses WHERE id=?`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return hash, err
}

func (s *Store) AddArtifact(ctx context.Context, a Artifact) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts(id,analysis_id,kind,name,sha256,size,content_type)
	  VALUES(?,?,?,?,?,?,?)`, a.ID, a.AnalysisID, a.Kind, a.Name, a.SHA256, a.Size, a.ContentType)
	return err
}

func (s *Store) Artifacts(ctx context.Context, analysisID string) ([]Artifact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,analysis_id,kind,name,sha256,size,content_type
	  FROM artifacts WHERE analysis_id=? ORDER BY kind,name`, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.ID, &a.AnalysisID, &a.Kind, &a.Name, &a.SHA256, &a.Size, &a.ContentType); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) Artifact(ctx context.Context, analysisID, artifactID string) (Artifact, error) {
	var a Artifact
	err := s.db.QueryRowContext(ctx, `SELECT id,analysis_id,kind,name,sha256,size,content_type
	  FROM artifacts WHERE analysis_id=? AND id=?`, analysisID, artifactID).
		Scan(&a.ID, &a.AnalysisID, &a.Kind, &a.Name, &a.SHA256, &a.Size, &a.ContentType)
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return a, err
}

func (s *Store) Prune(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM analyses
	  WHERE finished_at IS NOT NULL AND finished_at < ? AND state IN (?,?,?)`,
		before.UTC().Format(time.RFC3339Nano),
		analysisv1.AnalysisState_ANALYSIS_STATE_SUCCEEDED,
		analysisv1.AnalysisState_ANALYSIS_STATE_FAILED,
		analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED)
	return err
}

func (s *Store) ReferencedHashes(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `
	  SELECT sample_sha256 FROM analyses
	  UNION SELECT report_sha256 FROM analyses WHERE report_sha256 <> ''
	  UNION SELECT sha256 FROM artifacts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hashes := make(map[string]struct{})
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes[hash] = struct{}{}
	}
	return hashes, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAnalysis(row scanner) (*analysisv1.Analysis, error) {
	var (
		a                        analysisv1.Analysis
		state                    int32
		options                  []byte
		created, started, finish string
	)
	err := row.Scan(&a.Id, &state, &a.Filename, &a.SampleSha256, &a.SampleSize, &options,
		&created, &started, &finish, &a.ErrorCode, &a.ErrorMessage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.State = analysisv1.AnalysisState(state)
	a.Options = &analysisv1.AnalysisOptions{}
	if err := protojson.Unmarshal(options, a.Options); err != nil {
		return nil, err
	}
	a.CreatedAt = parseTimestamp(created)
	a.StartedAt = parseTimestamp(started)
	a.FinishedAt = parseTimestamp(finish)
	return &a, nil
}

func parseTimestamp(value string) *timestamppb.Timestamp {
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}

func EncodePageToken(t time.Time) string {
	return strconv.FormatInt(t.UnixNano(), 10)
}
