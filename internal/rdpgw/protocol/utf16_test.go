package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeUTF16ASCII(t *testing.T) {
	got := EncodeUTF16("AB")
	want := []byte{0x41, 0x00, 0x42, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestDecodeUTF16ASCII(t *testing.T) {
	got, err := DecodeUTF16([]byte{0x68, 0x00, 0x69, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi" {
		t.Fatalf("expected %q, got %q", "hi", got)
	}
}

func TestDecodeUTF16TrailingNull(t *testing.T) {
	b := append(EncodeUTF16("hi"), 0x00, 0x00)
	got, err := DecodeUTF16(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi" {
		t.Fatalf("expected %q, got %q", "hi", got)
	}
}

func TestDecodeUTF16OddLength(t *testing.T) {
	if _, err := DecodeUTF16([]byte{0x00}); err == nil {
		t.Fatal("expected error for odd-length input")
	}
}

func TestEncodeDecodeUTF16Unicode(t *testing.T) {
	input := "snowman-\u2603"
	encoded := EncodeUTF16(input)
	got, err := DecodeUTF16(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != input {
		t.Fatalf("expected %q, got %q", input, got)
	}
}
