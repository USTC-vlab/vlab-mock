package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ref: https://go.dev/src/crypto/tls/generate_cert.go
func GenSelfSignedTLSCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"USTC"},
			Organization: []string{"USTC Vlab Mock Testing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: priv}, nil
}

func PVECheckAuth(c *gin.Context) error {
	ticket, err := c.Cookie("PVEAuthCookie")
	if err != nil || ticket != "ticket" {
		return err
	}
	csrfToken := c.GetHeader("CSRFPreventionToken")
	if csrfToken != "CSRFPreventionToken" {
		return errors.New("invalid CSRFPreventionToken")
	}
	return nil
}

func mockPveServer(r *gin.Engine) error {
	// as https://github.com/gin-gonic/gin/pull/2823 is not being merged for over 1 yr
	// so have to write /api2/json/ before all routers
	r.POST("/api2/json/access/ticket", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		// just check if username and password are not empty
		if username == "" || password == "" || !strings.HasSuffix(username, "@pve") {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		c.JSON(200, gin.H{
			"data": gin.H{
				"username":            username,
				"ticket":              "ticket",
				"CSRFPreventionToken": "CSRFPreventionToken",
			},
		})
	})
	r.GET("/api2/json/nodes/:node/storage/:storage/content", func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		fmt.Println(c.Cookie("PVEAuthCookie"))
		fmt.Println(c.GetHeader("CSRFPreventionToken"))
		_ = c.Param("node")
		storage := c.Param("storage")

		content := c.Query("content")
		if content != "vztmpl" {
			// No content
			c.Data(400, "", []byte(""))
		}

		type StorageContent struct {
			Format string `json:"format"`
			Size   int64  `json:"size"`
			Volid  string `json:"volid"`
		}
		response := make([]StorageContent, 0)
		response = append(response, StorageContent{
			Format: "tgz",
			Size:   231060971,
			Volid:  storage + ":vztmpl/debian-10-standard_10.7-1_amd64.tar.gz",
		})
		response = append(response, StorageContent{
			Format: "tgz",
			Size:   243431756,
			Volid:  storage + ":vztmpl/debian-11-standard_11.0-1_amd64.tar.gz",
		})
		c.JSON(200, gin.H{
			"data": response,
		})
	})

	cert, err := GenSelfSignedTLSCertificate()
	if err != nil {
		panic(err)
	}

	server := http.Server{
		Addr:      "127.0.0.1:8006",
		Handler:   r.Handler(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	return server.ListenAndServeTLS("", "")
}

func mockPostCreationServer(r *gin.Engine) error {
	panic("not implemented")
	// r.Run("127.0.0.1:8090")
}

func main() {
	var mockType string
	flag.StringVar(&mockType, "mock", "pve", "pve or post_creation")
	flag.Parse()

	r := gin.Default()
	// make gin happy
	r.SetTrustedProxies([]string{})

	switch mockType {
	case "pve":
		panic(mockPveServer(r))
	case "post_creation":
		panic(mockPostCreationServer(r))
	default:
		panic(fmt.Sprintf("unknown mock type: %s", mockType))
	}
}
