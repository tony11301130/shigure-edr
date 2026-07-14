package tasks

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func listDirectory(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	max := intArg(args, "max_entries", 100)
	if max <= 0 || max > 500 {
		max = 100
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, e := range entries {
		info, _ := e.Info()
		row := map[string]any{"name": e.Name(), "is_dir": e.IsDir()}
		if info != nil {
			row["size"] = info.Size()
			row["mode"] = info.Mode().String()
			row["mod_time"] = info.ModTime().UTC().Format(time.RFC3339)
		}
		out = append(out, row)
		if len(out) >= max {
			break
		}
	}
	return map[string]any{"path": path, "entries": out, "truncated": len(entries) > len(out)}, nil
}

func readFileChunk(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	reason, caseID, err := evidenceContext(args)
	if err != nil {
		return err.(blockedEvidence).Result, ErrBlocked
	}
	offset := int64(intArg(args, "offset", 0))
	maxBytes, ok := explicitIntArg(args, "max_bytes")
	if !ok {
		return blockedEvidenceResult("read_file_chunk", "max_bytes_required"), ErrBlocked
	}
	if maxBytes <= 0 || maxBytes > 65536 {
		return blockedEvidenceResult("read_file_chunk", "max_bytes_out_of_range"), ErrBlocked
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	data := buf[:n]
	chunkHash := sha256.Sum256(data)
	return map[string]any{"path": path, "offset": offset, "bytes_read": n, "base64": base64.StdEncoding.EncodeToString(data), "text_preview": safePreview(data), "sha256": hex.EncodeToString(chunkHash[:]), "reason": reason, "case_id": caseID, "policy_version": PolicyVersion}, nil
}

func copyFileTask(args map[string]any) (map[string]any, error) {
	src, _ := args["source_path"].(string)
	dst, _ := args["destination_path"].(string)
	if src == "" || dst == "" {
		return nil, errors.New("source_path and destination_path required")
	}
	bytes, err := copyFile(src, dst)
	if err != nil {
		return nil, err
	}
	return map[string]any{"source_path": src, "destination_path": dst, "bytes_copied": bytes}, nil
}

func collectFile(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	reason, caseID, err := evidenceContext(args)
	if err != nil {
		return err.(blockedEvidence).Result, ErrBlocked
	}
	maxBytes, ok := explicitIntArg(args, "max_bytes")
	if !ok {
		return blockedEvidenceResult("collect_file", "max_bytes_required"), ErrBlocked
	}
	if maxBytes <= 0 || maxBytes > 10*1024*1024 {
		return blockedEvidenceResult("collect_file", "max_bytes_out_of_range"), ErrBlocked
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}
	if info.Size() > int64(maxBytes) {
		return map[string]any{"path": path, "size": info.Size(), "max_bytes": maxBytes, "blocked": true, "reason": "file_too_large", "policy_version": PolicyVersion, "case_id": caseID}, ErrBlocked
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	sha := hex.EncodeToString(h[:])
	return map[string]any{
		"path":           path,
		"size":           len(data),
		"sha256":         sha,
		"reason":         reason,
		"case_id":        caseID,
		"policy_version": PolicyVersion,
		"upload_file": map[string]any{
			"kind":           "file",
			"path":           path,
			"sha256":         sha,
			"size":           len(data),
			"content_base64": base64.StdEncoding.EncodeToString(data),
			"metadata":       map[string]any{"mod_time": info.ModTime().UTC().Format(time.RFC3339), "mode": info.Mode().String(), "reason": reason, "case_id": caseID, "policy_version": PolicyVersion},
		},
	}, nil
}

type blockedEvidence struct {
	Result map[string]any
}

func (e blockedEvidence) Error() string {
	if reason, _ := e.Result["reason"].(string); reason != "" {
		return reason
	}
	return ErrBlocked.Error()
}

func evidenceContext(args map[string]any) (string, string, error) {
	reason, _ := args["reason"].(string)
	if strings.TrimSpace(reason) == "" {
		return "", "", blockedEvidence{Result: blockedEvidenceResult("", "reason_required")}
	}
	caseID, _ := args["case_id"].(string)
	if strings.TrimSpace(caseID) == "" {
		return "", "", blockedEvidence{Result: blockedEvidenceResult("", "case_id_required")}
	}
	return reason, caseID, nil
}

func blockedEvidenceResult(taskType, reason string) map[string]any {
	out := map[string]any{"blocked": true, "reason": reason, "policy_version": PolicyVersion, "response_mode": "read_only"}
	if taskType != "" {
		out["task_type"] = taskType
	}
	return out
}

func explicitIntArg(args map[string]any, key string) (int, bool) {
	v, ok := args[key]
	if !ok {
		return 0, false
	}
	return intArg(map[string]any{key: v}, key, 0), true
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, in)
}

func safePreview(data []byte) string {
	s := string(data)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			return r
		}
		return '�'
	}, s)
	if len(s) > 4096 {
		return s[:4096]
	}
	return s
}
