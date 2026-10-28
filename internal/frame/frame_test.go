package frame

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// 帧格式契约（设计 §2）：[4B len LE int32][4B datatype LE int32][payload]，len = 4 + len(payload)
func TestEncodeFrame(t *testing.T) {
	got := Encode(1, []byte(`{"a":1}`))
	want := []byte{}
	var b []byte
	b = make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(4+7))
	want = append(want, b...)
	b2 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b2, uint32(1))
	want = append(want, b2...)
	want = append(want, []byte(`{"a":1}`)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestEncodeEmptyPayload(t *testing.T) {
	got := Encode(14, nil)
	if len(got) != 8 {
		t.Fatalf("want 8 bytes header only, got %d", len(got))
	}
	if binary.LittleEndian.Uint32(got[:4]) != 4 {
		t.Fatalf("len prefix want 4, got %d", binary.LittleEndian.Uint32(got[:4]))
	}
}

// step23 裸帧：[4B len][content]，无 datatype
func TestEncodeRaw(t *testing.T) {
	content := []byte("hello")
	got := EncodeRaw(content)
	if binary.LittleEndian.Uint32(got[:4]) != 5 {
		t.Fatalf("raw len prefix want 5, got %d", binary.LittleEndian.Uint32(got[:4]))
	}
	if !bytes.Equal(got[4:], content) {
		t.Fatalf("raw content mismatch: %q", got[4:])
	}
}

func TestReadFrameRoundtrip(t *testing.T) {
	orig := Encode(131, []byte(`{"url":"http://x"}`))
	dt, payload, err := Read(bytes.NewReader(orig))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if dt != 131 {
		t.Fatalf("datatype want 131, got %d", dt)
	}
	if string(payload) != `{"url":"http://x"}` {
		t.Fatalf("payload mismatch: %q", payload)
	}
}

func TestReadRawRoundtrip(t *testing.T) {
	orig := EncodeRaw([]byte("filecontent"))
	content, err := ReadRaw(bytes.NewReader(orig))
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if string(content) != "filecontent" {
		t.Fatalf("content mismatch: %q", content)
	}
}

// 分片到达：帧内容分多次 Write 仍能读出（粘包/半包）
func TestReadFrameChunked(t *testing.T) {
	orig := Encode(7, []byte(`{"file":"/x"}`))
	// 逐字节喂入
	r := io.MultiReader(bytes.NewReader(orig[:3]), bytes.NewReader(orig[3:5]), bytes.NewReader(orig[5:]))
	dt, payload, err := Read(r)
	if err != nil {
		t.Fatalf("Read chunked: %v", err)
	}
	if dt != 7 || string(payload) != `{"file":"/x"}` {
		t.Fatalf("chunked read mismatch: dt=%d payload=%q", dt, payload)
	}
}

// 长度前缀 < 4：无法容纳 datatype，协议违规
func TestReadFrameLenTooSmall(t *testing.T) {
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint32(bad[:4], 2)
	_, _, err := Read(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("want error for len<4 frame, got nil")
	}
}

// 负长度：垃圾帧
func TestReadFrameNegativeLen(t *testing.T) {
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint32(bad[:4], 0xFFFFFFFF) // -1
	_, _, err := Read(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("want error for negative len, got nil")
	}
}

// 对端在帧中途关闭
func TestReadFrameUnexpectedEOF(t *testing.T) {
	orig := Encode(1, []byte("abcdefgh"))
	_, _, err := Read(bytes.NewReader(orig[:10])) // 截断 payload
	if err == nil {
		t.Fatal("want error for truncated frame, got nil")
	}
}

func TestReadRawEmptyContent(t *testing.T) {
	content, err := ReadRaw(bytes.NewReader(EncodeRaw(nil)))
	if err != nil {
		t.Fatalf("ReadRaw empty: %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("want empty content, got %q", content)
	}
}
