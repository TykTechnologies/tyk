package main

import (
	"github.com/TykTechnologies/tyk/gateway"
)

func main() {
	//f, err := os.Create("trace-copybuffer.out")
	//if err != nil {
	//	panic(err)
	//}
	//defer f.Close()
	//
	//err = trace.Start(f)
	//if err != nil {
	//	panic(err)
	//}
	//defer trace.Stop()

	gateway.Start()
}
