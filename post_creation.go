package main

import "github.com/gin-gonic/gin"

func mockPostCreationServer(r *gin.Engine) error {
	r.POST("/set/:node/:vmid", func(c *gin.Context) {
		c.Data(200, "", []byte(""))
	})
	return r.Run("127.0.0.1:8090")
}
