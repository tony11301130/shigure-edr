package tasks

import "testing"

func TestParseWindowsTasklistCSV(t *testing.T) {
	rows := parseWindowsTasklistCSV("\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n\"cmd.exe\",\"4242\",\"Console\",\"1\",\"4,096 K\"\r\n")
	if len(rows) != 2 {
		t.Fatalf("expected two rows, got %#v", rows)
	}
	if rows[1]["image_name"] != "cmd.exe" || rows[1]["pid"] != 4242 {
		t.Fatalf("unexpected parsed row %#v", rows[1])
	}
}

func TestParseWindowsNetstatANO(t *testing.T) {
	rows := parseWindowsNetstatANO(`
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       980
  TCP    192.168.1.117:49714    93.184.216.34:443      ESTABLISHED     4242
  UDP    0.0.0.0:5353           *:*                                    1234
`)
	if len(rows) != 3 {
		t.Fatalf("expected three rows, got %#v", rows)
	}
	if rows[0]["state"] != "LISTENING" || rows[0]["pid"] != 980 {
		t.Fatalf("bad tcp row %#v", rows[0])
	}
	if rows[2]["protocol"] != "UDP" || rows[2]["pid"] != 1234 {
		t.Fatalf("bad udp row %#v", rows[2])
	}
}
