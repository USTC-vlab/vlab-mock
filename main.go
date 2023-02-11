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
	"strconv"
	"strings"
	"sync"
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

type LXCResource struct {
	Vmid   int    `json:"vmid"`
	Mem    int    `json:"mem"`
	Status string `json:"status"`
	Name   string `json:"name"`
	Uptime int    `json:"uptime"`
	Lock   string `json:"lock"`
	Node   string `json:"node"`
	Maxmem int    `json:"maxmem"`
}

var containers = []LXCResource{}
var containerMutex = &sync.Mutex{}

func createWait(vmid int) {
	// Mutex
	time.Sleep(10 * time.Second)
	containerMutex.Lock()
	defer containerMutex.Unlock()
	for i, container := range containers {
		if container.Vmid == vmid {
			fmt.Println("Unlocked container (mark as creation done)", vmid)
			containers[i].Lock = ""
		}
	}
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
			Volid:  storage + ":vztmpl/vlab-debian-10-standard_10.7-1_amd64.tar.gz",
		})
		response = append(response, StorageContent{
			Format: "tgz",
			Size:   243431756,
			Volid:  storage + ":vztmpl/vlab-debian-11-standard_11.0-1_amd64.tar.gz",
		})
		c.JSON(200, gin.H{
			"data": response,
		})
	})
	r.GET("/api2/json/cluster/resources", func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		type_ := c.Query("type")
		if type_ != "vm" {
			// not implemented
			c.Data(400, "", []byte(""))
			return
		}
		c.JSON(200, gin.H{
			"data": containers,
		})
	})
	r.POST("/api2/json/nodes/:node/lxc", func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		node := c.Param("node")
		vmid, err := strconv.Atoi(c.PostForm("vmid"))
		if err != nil {
			fmt.Printf("invalid vmid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}
		name := c.PostForm("name")

		containerMutex.Lock()
		defer containerMutex.Unlock()
		for _, container := range containers {
			if container.Vmid == vmid {
				fmt.Printf("container %d exists", vmid)
				c.Data(400, "", []byte(""))
				return
			}
		}
		containers = append(containers, LXCResource{
			Vmid:   vmid,
			Mem:    1024,
			Maxmem: 1024000,
			Status: "stopped",
			Name:   name,
			Uptime: 0,
			Lock:   "create",
			Node:   node,
		})
		go createWait(vmid)

		upid := "UPID:" + node + ":00000000:00000000:00000000:vzcreate:" + strconv.Itoa(vmid) + ":mock@pve:"

		c.JSON(200, gin.H{
			"data": upid,
		})
	})
	r.GET("/api2/json/nodes/:node/lxc/:vmid/config", func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		vmid := c.Param("vmid")
		_ = c.Param("node")
		vmidInt, err := strconv.Atoi(vmid)
		if err != nil {
			_ = fmt.Errorf("invalid vmid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}

		containerMutex.Lock()
		defer containerMutex.Unlock()
		for _, container := range containers {
			if container.Vmid == vmidInt {
				c.JSON(200, gin.H{
					"data": container,
				})
				return
			}
		}
	})
	r.GET("/api2/json/nodes/:node/tasks/:upid/status", func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		_ = c.Param("node")
		upid := c.Param("upid")
		upid_parts := strings.Split(upid, ":")
		if len(upid_parts) != 9 {
			fmt.Printf("invalid upid: %s\n", upid)
			c.Data(400, "", []byte(""))
			return
		}
		vmid, err := strconv.Atoi(upid_parts[6])
		if err != nil {
			fmt.Printf("invalid upid: %v\n", err)
			c.Data(400, "", []byte(""))
			return
		}
		event := upid_parts[5]
		if err != nil {
			fmt.Printf("invalid upid: %v\n", err)
			c.Data(400, "", []byte(""))
			return
		}
		fmt.Printf("vmid: %d, event: %s\n", vmid, event)
		if event != "vzcreate" {
			// not implemented
			c.Data(400, "", []byte(""))
			return
		}
		containerMutex.Lock()
		defer containerMutex.Unlock()
		for _, container := range containers {
			if container.Vmid == vmid {
				if container.Lock == "create" {
					c.JSON(200, gin.H{
						"data": gin.H{
							"status": "running",
						},
					})
					return
				}
				c.JSON(200, gin.H{
					"data": gin.H{
						"status":     "stopped",
						"exitstatus": "OK",
					},
				})
				return
			}
		}
		c.Data(404, "", []byte(""))
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
	r.POST("/set/:node/:vmid", func(c *gin.Context) {
		c.Data(200, "", []byte(""))
	})
	return r.Run("127.0.0.1:8090")
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
