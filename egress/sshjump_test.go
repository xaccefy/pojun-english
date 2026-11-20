package egress

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// SOCKS5 CONNECT 握手 + 双向转发（用本地 echo 服务代替 SSH 跳板）。
func TestSOCKSCONNECTForwards(t *testing.T) {
	// echo 目标
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()

	// SOCKS 服务
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleSOCKS(c, func(network, addr string) (net.Conn, error) { return net.Dial(network, addr) })
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("greeting 失败: %v %v", reply, err)
	}
	// CONNECT 到 echo
	host, portStr, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip := net.ParseIP(host).To4()
	req = append(req, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("connect 回复失败: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("connect 被拒: %v", resp)
	}
	// echo
	msg := []byte("hello-socks")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("转发失败: %q %v", got, err)
	}
}
