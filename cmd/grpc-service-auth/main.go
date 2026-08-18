package main

import (
	"fmt"
	"grpc-service/internal/config"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)
}
