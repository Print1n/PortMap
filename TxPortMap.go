package main

import (
	"fmt"
	"github.com/Print1n/PortMap/portmap"
	_ "github.com/projectdiscovery/fdmax/autofdmax" //Add automatic increase of file descriptors in linux
	"time"
)

// 建议扫描top100或者top1000端口时使用顺序扫描，其它情况使用随机扫描
func main() {
	startTime := time.Now()
	e := portmap.New()
	e.Wg.Add(10000)
	for i := 0; i < 10000; i++ {
		go e.Worker(e.TaskChan, e.Wg)
	}

	target1 := portmap.Addr{Ip: "116.62.119.49", Port: 22}
	//target := common.Addr{Ip: "220.181.38.251", Port: uint64(port)}
	target := portmap.Addr{Ip: "47.98.223.150", Port: 3306}
	e.TaskChan <- target
	e.TaskChan <- target1

	close(e.TaskChan)

	e.Wg.Wait()
	/*	scanner := e.Scanner("116.62.119.49", 22)
		fmt.Printf("scanner:%+v\n", *scanner)
		marshal, err := json.Marshal(scanner)
		if err != nil {
			fmt.Printf("json marshal error: %v\n", err)
		}
		fmt.Println(string(marshal))*/
	fmt.Println("total time: ", time.Since(startTime))
}
