package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create blob root: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) Put(r io.Reader, maxBytes int64) (hash string, size int64, err error) {
	tmp, err := os.CreateTemp(s.root, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if n > maxBytes {
		return "", 0, fmt.Errorf("upload exceeds %d bytes", maxBytes)
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, err
	}
	hash = hex.EncodeToString(h.Sum(nil))
	dst := s.Path(hash)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", 0, err
	}
	if err := os.Rename(name, dst); err != nil {
		if !errors.Is(err, os.ErrExist) {
			if _, statErr := os.Stat(dst); statErr != nil {
				return "", 0, err
			}
		}
	}
	return hash, n, nil
}

func (s *Store) PutBytes(data []byte) (string, int64, error) {
	return s.Put(&byteReader{data: data}, int64(len(data)))
}

func (s *Store) Open(hash string) (*os.File, error) {
	if !validHash(hash) {
		return nil, fmt.Errorf("invalid blob hash")
	}
	return os.Open(s.Path(hash))
}

func (s *Store) Path(hash string) string {
	return filepath.Join(s.root, hash[:2], hash)
}

func (s *Store) GC(ctx context.Context, keep map[string]struct{}) error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	for _, prefix := range entries {
		if !prefix.IsDir() || len(prefix.Name()) != 2 {
			continue
		}
		dir := filepath.Join(s.root, prefix.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if file.IsDir() || !validHash(file.Name()) || !strings.HasPrefix(file.Name(), prefix.Name()) {
				continue
			}
			if _, ok := keep[file.Name()]; !ok {
				if err := os.Remove(filepath.Join(dir, file.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
		_ = os.Remove(dir)
	}
	return nil
}

type byteReader struct {
	data []byte
}

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
