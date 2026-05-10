package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

type SecureChannel struct {
	SecretKey []byte
}

func NewSecureChannel() *SecureChannel {
	key := make([]byte, 32)
	rand.Read(key)

	return &SecureChannel{
		SecretKey: key,
	}
}

func (s *SecureChannel) GenerateHMAC(
	message []byte,
) string {
	h := hmac.New(
		sha256.New,
		s.SecretKey,
	)

	h.Write(message)

	return hex.EncodeToString(
		h.Sum(nil),
	)
}

func (s *SecureChannel) VerifyHMAC(
	message []byte,
	signature string,
) bool {
	expected := s.GenerateHMAC(message)

	return hmac.Equal(
		[]byte(expected),
		[]byte(signature),
	)
}

func (s *SecureChannel) StartTLSServer() {
	cert, err := tls.LoadX509KeyPair(
		"server.crt",
		"server.key",
	)

	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
	}

	listener, err := tls.Listen(
		"tcp",
		":8443",
		config,
	)

	if err != nil {
		panic(err)
	}

	defer listener.Close()

	fmt.Println("TLS server started")

	for {
		conn, err := listener.Accept()

		if err != nil {
			continue
		}

		go s.HandleConnection(conn)
	}
}

func (s *SecureChannel) HandleConnection(
	conn net.Conn,
) {
	defer conn.Close()

	buffer := make([]byte, 4096)

	n, err := conn.Read(buffer)

	if err != nil {
		return
	}

	data := buffer[:n]

	signature := s.GenerateHMAC(data)

	conn.Write([]byte(signature))
}

func (s *SecureChannel) SecureTransmit(
	conn net.Conn,
	data []byte,
) error {
	signature := s.GenerateHMAC(data)

	packet := append(
		data,
		[]byte(signature)...,
	)

	_, err := conn.Write(packet)

	return err
}

func (s *SecureChannel) ReceiveSecure(
	conn net.Conn,
) ([]byte, error) {
	buffer := make([]byte, 4096)

	n, err := io.ReadFull(
		conn,
		buffer,
	)

	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

func main() {
	channel := NewSecureChannel()

	message := []byte(
		"Critical military communication",
	)

	signature := channel.GenerateHMAC(
		message,
	)

	fmt.Println(signature)
}