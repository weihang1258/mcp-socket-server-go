package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func timeNow() time.Time     { return time.Now() }
func timeSec() time.Duration { return time.Second }
func sleepMs(ms int)         { time.Sleep(time.Duration(ms) * time.Millisecond) }

// dt1 响应解包：[4B i][gzip JSON]
func unwrapGzipResp(t *testing.T, resp []byte) []byte {
	t.Helper()
	if len(resp) < 4 {
		t.Fatalf("missing gzip length prefix: %q", resp)
	}
	n := binary.LittleEndian.Uint32(resp[:4])
	zr, err := gzip.NewReader(bytes.NewReader(resp[4 : 4+n]))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	out, _ := io.ReadAll(zr)
	return out
}

// dt1 正常执行：{code,stdout,stderr}，gzip 帧响应
func TestDT1ExecBasic(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"args": "echo hello", "wait": true})
	resp, err := runDT(t, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	if err := json.Unmarshal(unwrapGzipResp(t, resp), &out); err != nil {
		t.Fatal(err)
	}
	if out.Code != 0 || out.Stdout != "hello\n" {
		t.Fatalf("want code=0 stdout=hello\\n, got %+v", out)
	}
}

// dt1 wait=false：立即回 "null" gzip 帧（quirk：不是不回）；命令真实执行
func TestDT1WaitFalse(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	payload, _ := json.Marshal(map[string]any{
		"args": "touch " + marker, "wait": false,
	})
	resp, err := runDT(t, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := unwrapGzipResp(t, resp); string(got) != "null" {
		t.Fatalf(`wait=false want gzip "null", got %q`, got)
	}
	// 异步命令最终应执行（给调度留时间）
	deadline := time.Now().Add(2 * time.Second)
	for timeNow().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("async command never ran")
}

// dt1 cwd 与 env：env 键整替换环境（Python dict(os.environ if env is None else env)）
func TestDT1CwdEnv(t *testing.T) {
	dir := t.TempDir()
	payload, _ := json.Marshal(map[string]any{
		"args": "pwd", "cwd": dir, "wait": true,
	})
	resp, _ := runDT(t, 1, payload)
	var out struct {
		Stdout string `json:"stdout"`
	}
	json.Unmarshal(unwrapGzipResp(t, resp), &out)
	if out.Stdout != dir+"\n" {
		t.Fatalf("cwd wrong: %q", out.Stdout)
	}

	// env 替换：只给 MYVAR，PATH 没了 → sh 都找不到 → code=-1 异常路径
	payload, _ = json.Marshal(map[string]any{
		"args": "echo $MYVAR", "wait": true,
		"env": map[string]string{"MYVAR": "v1"},
	})
	resp, err := runDT(t, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	var out2 struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
	}
	if err := json.Unmarshal(unwrapGzipResp(t, resp), &out2); err != nil {
		t.Fatal(err)
	}
	// env 整替换后无 PATH，但 /bin/sh 绝对路径 + echo 内建仍可跑：stdout 必须 = v1
	if out2.Code != 0 || out2.Stdout != "v1\n" {
		t.Fatalf("env replacement wrong: %+v", out2)
	}
}

// dt1 shell 命令非零退出：code 透传
func TestDT1ExitCode(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"args": "exit 7", "wait": true})
	resp, _ := runDT(t, 1, payload)
	var out struct {
		Code int `json:"code"`
	}
	json.Unmarshal(unwrapGzipResp(t, resp), &out)
	if out.Code != 7 {
		t.Fatalf("want code 7, got %d", out.Code)
	}
}

// dt1 畸形 JSON payload → 断连
func TestDT1JSONPayloadError(t *testing.T) {
	if _, err := runDT(t, 1, []byte("not-json")); err == nil {
		t.Fatal("bad json must disconnect")
	}
}

// dt15 unzip：list-args 语义（-o/-P/basename/-d），cwd=dirname，恒回 b"ok"
func TestDT15Unzip(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	calls := filepath.Join(fake, "calls")
	os.WriteFile(filepath.Join(fake, "unzip"), []byte("#!/bin/sh\necho \"$@\" >> "+calls+"\necho \"PWD=$(pwd)\" >> "+calls+"\n"), 0o755)

	z := filepath.Join(fake, "sub", "pkg.zip")
	os.MkdirAll(filepath.Dir(z), 0o755)
	payload, _ := json.Marshal(map[string]any{
		"file": z, "outdir": "/tmp/out", "passwd": "pw1", "overwrite": true,
	})
	resp, err := runDT(t, 15, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ok" {
		t.Fatalf("dt15 must return bare ok, got %q", resp)
	}
	data, _ := os.ReadFile(calls)
	if !bytes.Contains(data, []byte("-o -P pw1 pkg.zip -d /tmp/out")) {
		t.Fatalf("unzip argv wrong: %q", data)
	}
	if !bytes.Contains(data, []byte("PWD="+filepath.Dir(z)+"\n")) {
		t.Fatalf("cwd must be file dir: %q", data)
	}
}

// dt15 overwrite=false 不带 -o
func TestDT15NoOverwrite(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	calls := filepath.Join(fake, "calls")
	os.WriteFile(filepath.Join(fake, "unzip"), []byte("#!/bin/sh\necho \"$@\" >> "+calls+"\n"), 0o755)
	payload, _ := json.Marshal(map[string]any{"file": "/d/x.zip", "overwrite": false})
	if _, err := runDT(t, 15, payload); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(calls)
	if bytes.Contains(data, []byte("-o")) {
		t.Fatalf("overwrite=false must omit -o: %q", data)
	}
}

// dt15 unzip 缺失：静默返回，仍 b"ok"（quirk）
func TestDT15UnzipMissingStillOK(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake) // 空 PATH，无 unzip
	payload, _ := json.Marshal(map[string]any{"file": "/d/x.zip"})
	resp, err := runDT(t, 15, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ok" {
		t.Fatalf("unzip missing must still return ok, got %q", resp)
	}
}
