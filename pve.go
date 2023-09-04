package main

import (
	"crypto/tls"
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
	// Remove csrfToken check, as new proxmoxer will only send it when method != GET
	// csrfToken := c.GetHeader("CSRFPreventionToken")
	// if csrfToken != "CSRFPreventionToken" {
	// 	return errors.New("invalid CSRFPreventionToken")
	// }
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

func Status(c *gin.Context) {
	vmid := c.Param("vmid")
	_ = c.Param("node")
	vmidInt, err := strconv.Atoi(vmid)
	if err != nil {
		fmt.Printf("invalid vmid: %v", err)
		c.Data(400, "", []byte(""))
		return
	}
	vmsMutex.Lock()
	defer vmsMutex.Unlock()
	for _, vm := range vms {
		if vm.Vmid == vmidInt {
			c.JSON(200, gin.H{
				"data": vm,
			})
			return
		}
	}
	c.Data(404, "", []byte(""))
}

func Config(c *gin.Context) {
	vmid := c.Param("vmid")
	_ = c.Param("node")
	vmidInt, err := strconv.Atoi(vmid)
	if err != nil {
		fmt.Printf("invalid vmid: %v", err)
		c.Data(400, "", []byte(""))
		return
	}
	vmsMutex.Lock()
	defer vmsMutex.Unlock()
	for _, vm := range vms {
		if vm.Vmid == vmidInt {
			c.JSON(200, gin.H{
				"data": vm,
			})
			return
		}
	}
}

type Resource struct {
	Vmid     int    `json:"vmid"`
	Mem      int    `json:"mem"`
	Status   string `json:"status"`
	Name     string `json:"name"`
	Uptime   int    `json:"uptime"`
	Lock     string `json:"lock"`
	Node     string `json:"node"`
	Maxmem   int    `json:"maxmem"`
	Template int    `json:"template"`
	Type     string `json:"type"`
}

var vms = []Resource{}
var vmsMutex = &sync.Mutex{}

var tasks = map[int]string{}
var taskMutex = &sync.Mutex{}

func createWait(vmid int) {
	// Mutex
	time.Sleep(20 * time.Second)
	vmsMutex.Lock()
	defer vmsMutex.Unlock()
	for i, vm := range vms {
		if vm.Vmid == vmid {
			fmt.Println("Unlocked container/kvm (mark as creation done)", vmid)
			vms[i].Lock = ""
		}
	}
}

func taskWait(vmid int, action string) {
	time.Sleep(5 * time.Second)
	vmsMutex.Lock()
	defer vmsMutex.Unlock()
	for i, vm := range vms {
		if vm.Vmid == vmid {
			switch action {
			case "start":
				vms[i].Status = "running"
			case "stop":
				vms[i].Status = "stopped"
			case "reset":
				vms[i].Status = "running"
			case "reboot":
				vms[i].Status = "running"
			}
		}
	}
	taskMutex.Lock()
	defer taskMutex.Unlock()
	delete(tasks, vmid)
}

func mockPveServer(r *gin.Engine) error {
	// Create a KVM template
	vms = append(vms, Resource{
		Vmid:     101,
		Mem:      1024,
		Status:   "stopped",
		Name:     "vlab-kvm-debian-11",
		Uptime:   0,
		Lock:     "",
		Node:     "pv0",
		Maxmem:   1024000,
		Template: 1,
		Type:     "qemu",
	})
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
		vmsMutex.Lock()
		defer vmsMutex.Unlock()
		c.JSON(200, gin.H{
			"data": vms,
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

		vmsMutex.Lock()
		defer vmsMutex.Unlock()
		for _, vm := range vms {
			if vm.Vmid == vmid {
				fmt.Printf("vm %d exists\n", vmid)
				c.Data(400, "", []byte(""))
				return
			}
		}
		vms = append(vms, Resource{
			Vmid:   vmid,
			Mem:    1024,
			Maxmem: 1024000,
			Status: "stopped",
			Name:   name,
			Uptime: 0,
			Lock:   "create",
			Node:   node,
			Type:   "lxc",
		})
		go createWait(vmid)

		upid := "UPID:" + node + ":00000000:00000000:00000000:vzcreate:" + strconv.Itoa(vmid) + ":mock@pve:"

		c.JSON(200, gin.H{
			"data": upid,
		})
	}))
	r.GET("/api2/json/nodes/:node/lxc/:vmid/config", PVERequireAuth(func(c *gin.Context) {
		Config(c)
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
		if event != "vzcreate" && event != "qmclone" {
			if event == "vzstart" || event == "vzstop" || event == "vzreboot" ||
				event == "qmstart" || event == "qmstop" || event == "qmreset" ||
				event == "qmreboot" {

				taskMutex.Lock()
				defer taskMutex.Unlock()
				if _, ok := tasks[vmid]; ok {
					c.JSON(200, gin.H{
						"data": gin.H{
							"status": "running",
							"type":   event,
						},
					})
				} else {
					// assuming that this is a stopped task
					c.JSON(200, gin.H{
						"data": gin.H{
							"status":     "stopped",
							"exitstatus": "OK",
							"type":       event,
						},
					})
				}
				return
			} else if event == "resize" {
				c.JSON(200, gin.H{
					"data": gin.H{
						"status":     "stopped",
						"exitstatus": "OK",
						"type":       event,
					},
				})
				return
			}
			c.Data(400, "", []byte(""))
			return
		}
		// vzcreate / qmclone
		vmsMutex.Lock()
		defer vmsMutex.Unlock()
		for _, vm := range vms {
			if vm.Vmid == vmid {
				if vm.Lock == "create" {
					c.JSON(200, gin.H{
						"data": gin.H{
							"status": "running",
							"type":   "vzcreate",
						},
					})
					return
				} else if vm.Lock == "clone" {
					c.JSON(200, gin.H{
						"data": gin.H{
							"status": "running",
							"type":   "qmclone",
						},
					})
					return
				}
				var typ string
				if vm.Type == "lxc" {
					typ = "vzcreate"
				} else if vm.Type == "qemu" {
					typ = "qmclone"
				}
				c.JSON(200, gin.H{
					"data": gin.H{
						"status":     "stopped",
						"type":       typ,
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
		if action != "start" && action != "stop" && action != "reboot" {
			fmt.Printf("invalid action: %s", action)
			c.Data(400, "", []byte(""))
			return
		}
		vmsMutex.Lock()
		defer vmsMutex.Unlock()

		for _, container := range vms {
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
				case "reboot":
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
		vmsMutex.Lock()
		defer vmsMutex.Unlock()
		for i, container := range vms {
			if container.Vmid == vmidInt {
				if container.Lock != "" {
					fmt.Printf("container %d is locked", vmidInt)
					c.Data(400, "", []byte(""))
					return
				}
				vms = append(vms[:i], vms[i+1:]...)
				c.Data(200, "", []byte(""))
				taskMutex.Lock()
				defer taskMutex.Unlock()
				delete(tasks, vmidInt)
				return
			}
		}
		c.Data(404, "", []byte(""))
	}))
	r.GET("/api2/json/nodes/:node/lxc/:vmid/status/current", PVERequireAuth(func(c *gin.Context) {
		Status(c)
	}))
	r.POST("/api2/json/nodes/:node/qemu/:vmid/clone", PVERequireAuth(func(c *gin.Context) {
		vmid := c.Param("vmid")
		node := c.Param("node")
		new_vmid := c.PostForm("newid")
		new_vmidInt, err := strconv.Atoi(new_vmid)
		if err != nil {
			fmt.Printf("invalid newid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}
		name := c.PostForm("name")

		vmsMutex.Lock()
		defer vmsMutex.Unlock()
		for _, vm := range vms {
			if vm.Vmid == new_vmidInt {
				fmt.Printf("vm %s exists\n", vmid)
				c.Data(400, "", []byte(""))
				return
			}
		}
		vms = append(vms, Resource{
			Vmid:   new_vmidInt,
			Mem:    1024,
			Maxmem: 1024000,
			Status: "stopped",
			Name:   name,
			Uptime: 0,
			Lock:   "clone", // ??? Not sure here
			Node:   node,
			Type:   "qemu",
		})
		go createWait(new_vmidInt)

		upid := "UPID:" + node + ":00000000:00000000:00000000:qmclone:" + vmid + ":mock@pve:"

		c.JSON(200, gin.H{
			"data": upid,
		})
	}))
	r.GET("/api2/json/nodes/:node/qemu/:vmid/config", PVERequireAuth(func(c *gin.Context) {
		Config(c)
	}))
	r.GET("/api2/json/nodes/:node/qemu/:vmid/status/current", PVERequireAuth(func(c *gin.Context) {
		Status(c)
	}))
	r.POST("/api2/json/nodes/:node/qemu/:vmid/status/:action", PVERequireAuth(func(c *gin.Context) {
		vmid := c.Param("vmid")
		node := c.Param("node")
		vmidInt, err := strconv.Atoi(vmid)
		if err != nil {
			fmt.Printf("invalid vmid: %v", err)
			c.Data(400, "", []byte(""))
			return
		}
		action := c.Param("action")
		if action != "start" && action != "stop" && action != "reset" {
			fmt.Printf("invalid action: %s", action)
			c.Data(400, "", []byte(""))
			return
		}
		vmsMutex.Lock()
		defer vmsMutex.Unlock()

		for _, container := range vms {
			if container.Vmid == vmidInt {
				if container.Lock != "" {
					fmt.Printf("vm %d is locked\n", vmidInt)
					c.Data(400, "", []byte(""))
					return
				}
				switch action {
				case "start":
					if container.Status == "running" {
						fmt.Printf("vm %d is already running", vmidInt)
						c.Data(400, "", []byte(""))
						return
					}
				case "stop":
					if container.Status == "stopped" {
						fmt.Printf("vm %d is already stopped", vmidInt)
						c.Data(400, "", []byte(""))
						return
					}
				case "reset":
					if container.Status == "stopped" {
						fmt.Printf("vm %d is stopped", vmidInt)
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
		upid := "UPID:" + node + ":00000000:00000000:00000000:qm" + action + ":" + vmid + ":mock@pve:"
		c.JSON(200, gin.H{
			"data": upid,
		})
	}))
	r.PUT("/api2/json/nodes/:node/qemu/:vmid/config", PVERequireAuth(func(c *gin.Context) {
		// TODO
		// ignore this temporarily (sync API, returns null)
	}))
	r.PUT("/api2/json/nodes/:node/qemu/:vmid/resize", PVERequireAuth(func(c *gin.Context) {
		// TODO
		node := c.Param("node")
		vmid := c.Param("vmid")

		// resize is a sync API. resizing takes time
		time.Sleep(3 * time.Second)
		upid := "UPID:" + node + ":00000000:00000000:00000000:resize:" + vmid + ":mock@pve:"
		c.JSON(200, gin.H{
			"data": upid,
		})
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
