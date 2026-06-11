package tasks

import (
	"encoding/csv"
	"strconv"
	"strings"
)

func parseWindowsTasklistCSV(output string) []map[string]any {
	reader := csv.NewReader(strings.NewReader(output))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil
	}
	rows := []map[string]any{}
	for _, rec := range records {
		if len(rec) < 5 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(rec[1]))
		rows = append(rows, map[string]any{
			"image_name":   strings.TrimSpace(rec[0]),
			"pid":          pid,
			"session_name": strings.TrimSpace(rec[2]),
			"session_id":   strings.TrimSpace(rec[3]),
			"mem_usage":    strings.TrimSpace(rec[4]),
		})
	}
	return rows
}

func parseWindowsNetstatANO(output string) []map[string]any {
	rows := []map[string]any{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		row := map[string]any{"protocol": proto, "local_address": fields[1], "remote_address": fields[2]}
		if proto == "TCP" {
			if len(fields) < 5 {
				continue
			}
			row["state"] = fields[3]
			if pid, err := strconv.Atoi(fields[4]); err == nil {
				row["pid"] = pid
			}
		} else {
			if pid, err := strconv.Atoi(fields[3]); err == nil {
				row["pid"] = pid
			}
		}
		rows = append(rows, row)
	}
	return rows
}
