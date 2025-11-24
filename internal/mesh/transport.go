package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func dialTransportOption(tlsCfg TLSConfig) (grpc.DialOption, error) {
	if !tlsCfg.Enabled {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	if tlsCfg.CertPath == "" || tlsCfg.KeyPath == "" {
		return nil, errors.New("tls enabled but cert/key paths are empty")
	}
	cert, err := tls.LoadX509KeyPair(tlsCfg.CertPath, tlsCfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mesh tls cert: %w", err)
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
	}
	if tlsCfg.CAPath != "" {
		pool := x509.NewCertPool()
		caBytes, err := os.ReadFile(tlsCfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read mesh ca: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("append mesh ca cert failed")
		}
		config.RootCAs = pool
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(config)), nil
}
