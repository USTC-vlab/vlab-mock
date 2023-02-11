package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

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

func PVERequireAuth(f gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := PVECheckAuth(c)
		if err != nil {
			// No ticket
			c.Data(401, "", []byte(""))
			return
		}
		f(c)
	}
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

var tasks = map[int]string{}
var taskMutex = &sync.Mutex{}

func createWait(vmid int) {
	// Mutex
	time.Sleep(20 * time.Second)
	containerMutex.Lock()
	defer containerMutex.Unlock()
	for i, container := range containers {
		if container.Vmid == vmid {
			fmt.Println("Unlocked container (mark as creation done)", vmid)
			containers[i].Lock = ""
		}
	}
}

func taskWait(vmid int, action string) {
	time.Sleep(5 * time.Second)
	containerMutex.Lock()
	defer containerMutex.Unlock()
	for i, container := range containers {
		if container.Vmid == vmid {
			switch action {
			case "start":
				containers[i].Status = "running"
			case "stop":
				containers[i].Status = "stopped"
			case "restart":
				containers[i].Status = "running"
			}
		}
	}
	taskMutex.Lock()
	defer taskMutex.Unlock()
	delete(tasks, vmid)
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
	r.GET("/api2/json/nodes/:node/storage/:storage/content", PVERequireAuth(func(c *gin.Context) {
		fmt.Println(c.Cookie("PVEAuthCookie"))
		fmt.Println(c.GetHeader("CSRFPreventionToken"))
		_ = c.Param("node")
		storage := c.Param("storage")

		content := c.Query("content")
		if content != "vztmpl" {
			// No content
			c.Data(400, "", []byte(""))
			return
		}

		type StorageContent struct {
			Format string `json:"format"`
			Size   int64  `json:"size"`
			Volid  string `json:"volid"`
		}
		response := []StorageContent{
			{
				Format: "tgz",
				Size:   231060971,
				Volid:  storage + ":vztmpl/vlab-debian-10-standard_10.7-1_amd64.tar.gz",
			},
			{
				Format: "tgz",
				Size:   243431756,
				Volid:  storage + ":vztmpl/vlab-debian-11-standard_11.0-1_amd64.tar.gz",
			},
		}
		c.JSON(200, gin.H{
			"data": response,
		})
	}))
	r.GET("/api2/json/cluster/resources", PVERequireAuth(func(c *gin.Context) {
		type_ := c.Query("type")
		if type_ != "vm" {
			// not implemented
			c.Data(400, "", []byte(""))
			return
		}
		containerMutex.Lock()
		defer containerMutex.Unlock()
		c.JSON(200, gin.H{
			"data": containers,
		})
	}))
	r.POST("/api2/json/nodes/:node/lxc", PVERequireAuth(func(c *gin.Context) {
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
	}))
	r.GET("/api2/json/nodes/:node/lxc/:vmid/config", PVERequireAuth(func(c *gin.Context) {
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
	}))
	r.GET("/api2/json/nodes/:node/tasks/:upid/status", PVERequireAuth(func(c *gin.Context) {
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
			if event != "vzstart" && event != "vzstop" && event != "vzrestart" {
				taskMutex.Lock()
				defer taskMutex.Unlock()
				if _, ok := tasks[vmid]; ok {
					c.JSON(200, gin.H{
						"data": gin.H{
							"status": "running",
						},
					})
					return
				}
			}
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
	}))
	r.POST("/api2/json/nodes/:node/lxc/:vmid/status/:action", PVERequireAuth(func(c *gin.Context) {
		vmid := c.Param("vmid")
		node := c.Param("node")
		vmidInt, err := strconv.Atoi(vmid)
		if err != nil {
			fmt.Printf("invalid vmid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}
		action := c.Param("action")
		if action != "start" && action != "stop" && action != "restart" {
			fmt.Printf("invalid action: %s", action)
			c.Data(400, "", []byte(""))
			return
		}
		containerMutex.Lock()
		defer containerMutex.Unlock()

		for _, container := range containers {
			if container.Vmid == vmidInt {
				if container.Lock != "" {
					fmt.Printf("container %d is locked", vmidInt)
					c.Data(400, "", []byte(""))
					return
				}
				switch action {
				case "start":
					if container.Status == "running" {
						fmt.Printf("container %d is already running", vmidInt)
						c.Data(400, "", []byte(""))
						return
					}
				case "stop":
					if container.Status == "stopped" {
						fmt.Printf("container %d is already stopped", vmidInt)
						c.Data(400, "", []byte(""))
						return
					}
				case "restart":
					if container.Status == "stopped" {
						fmt.Printf("container %d is stopped", vmidInt)
						c.Data(400, "", []byte(""))
						return
					}
				}
			}
		}

		taskMutex.Lock()
		defer taskMutex.Unlock()
		if _, ok := tasks[vmidInt]; ok {
			fmt.Printf("task for vmid %d already exists", vmidInt)
			c.Data(400, "", []byte(""))
			return
		} else {
			tasks[vmidInt] = action
		}
		go taskWait(vmidInt, action)
		upid := "UPID:" + node + ":00000000:00000000:00000000:vz" + action + ":" + vmid + ":mock@pve:"
		c.JSON(200, gin.H{
			"data": upid,
		})
	}))
	r.DELETE("/api2/json/nodes/:node/lxc/:vmid", PVERequireAuth(func(c *gin.Context) {
		vmid := c.Param("vmid")
		vmidInt, err := strconv.Atoi(vmid)
		if err != nil {
			fmt.Printf("invalid vmid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}
		containerMutex.Lock()
		defer containerMutex.Unlock()
		for i, container := range containers {
			if container.Vmid == vmidInt {
				if container.Lock != "" {
					fmt.Printf("container %d is locked", vmidInt)
					c.Data(400, "", []byte(""))
					return
				}
				containers = append(containers[:i], containers[i+1:]...)
				c.Data(200, "", []byte(""))
				taskMutex.Lock()
				defer taskMutex.Unlock()
				delete(tasks, vmidInt)
				return
			}
		}
		c.Data(404, "", []byte(""))
	}))

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
