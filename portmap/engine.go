package portmap

import (
	"encoding/hex"
	"fmt"
	"github.com/Print1n/PortMap/Ginfo/Ghttp"
	"github.com/Print1n/PortMap/result"
	"go.uber.org/ratelimit"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	TaskIps     []Range
	TaskPorts   []Range
	ExcdPorts   []Range // 待排除端口
	ExcdIps     []Range // 待排除的Ip
	WorkerCount int
	TaskChan    chan Addr // 传递待扫描的ip端口对
	//DoneChan chan struct{}  // 任务完成通知
	Wg      *sync.WaitGroup
	Limiter ratelimit.Limiter
}

type Addr struct {
	Ip   string
	Port uint64
}

type ScanResult struct {
	WorkingEvent interface{}
	Banner       string
	Service      string
	Cert         string
	Target       string
	Port         uint64
	Time         string
}

type IdentificationPacket struct {
	Desc   string
	Packet []byte
}

type Range struct {
	Begin uint64
	End   uint64
}

var stIdentificationPacket [100]IdentificationPacket
var Writer result.Writer

// 初始化IdentificationProtocol到内存中
func init() {
	for i, packet := range IdentificationProtocol {
		szinfo := strings.Split(packet, "#")
		data, err := hex.DecodeString(szinfo[1])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		stIdentificationPacket[i].Desc = szinfo[0]
		stIdentificationPacket[i].Packet = data
	}
}

func New() *Engine {
	limit := ratelimit.New(limit)
	// 结果输出
	var err error
	Writer, err = result.NewStandardWriter(true, false)
	if err != nil {
		fmt.Printf("result.NewStandardWriter failed: %v\n", err)
		return nil
	}
	return &Engine{
		TaskChan:    make(chan Addr, 1000),
		WorkerCount: 10,
		Limiter:     limit,
		Wg:          &sync.WaitGroup{},
	}
}

func (e *Engine) Worker(target chan Addr, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()

		for addr := range target {
			e.Limiter.Take()
			e.Scanner(addr.Ip, addr.Port)
		}
	}()
}

func (e *Engine) Scanner(ip string, port uint64) {
	var dwSvc int
	var iRule = -1
	var bIsIdentification = false
	//var resultEvent *output.ResultEvent
	var scanResult *result.Event
	var packet []byte
	//var iCntTimeOut = 0

	// 端口开放状态，发送报文，获取响应
	// 先判断端口是不是优先识别协议端口
	for _, svc := range St_Identification_Port {
		if port == svc.Port {
			bIsIdentification = true
			iRule = svc.Identification_RuleId
			data := stIdentificationPacket[iRule].Packet
			dwSvc, scanResult = SendIdentificationPacketFunction(data, ip, port)
			break
		}
	}
	if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
		//Writer.Write(resultEvent)
		Writer.Write(scanResult)
		return
	}

	// 发送其他协议查询包
	for i := 0; i < iPacketMask; i++ {
		// 超时2次,不再识别
		if bIsIdentification && iRule == i {
			continue
		}
		if i == 0 {
			// 说明是http，数据需要拼装一下
			var szOption string
			if port == 80 {
				szOption = fmt.Sprintf("%s%s\r\n\r\n", stIdentificationPacket[0].Packet, ip)
			} else {
				szOption = fmt.Sprintf("%s%s:%d\r\n\r\n", stIdentificationPacket[0].Packet, ip, port)
			}
			packet = []byte(szOption)
		} else {
			packet = stIdentificationPacket[i].Packet
		}

		dwSvc, scanResult = SendIdentificationPacketFunction(packet, ip, port)
		if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
			Writer.Write(scanResult)
			return
		}
	}
	// 没有识别到服务，也要输出当前开放端口状态
	Writer.Write(scanResult)
	return
}

func SendIdentificationPacketFunction(data []byte, ip string, port uint64) (int, *result.Event) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	result := &result.Event{
		Target: ip,
		Info:   &result.Info{},
	}

	//fmt.Println(addr)
	var dwSvc = UNKNOWN_PORT
	conn, err := net.DialTimeout("tcp", addr, time.Duration(Timeout*1000)*time.Millisecond)
	if err != nil {
		// 端口是closed状态
		return SOCKET_CONNECT_FAILED, nil
	}

	defer conn.Close()

	// Write方法是非阻塞的

	if _, err := conn.Write(data); err != nil {
		// 端口是开放的
		//return dwSvc, even
		return dwSvc, result
	}

	// 直接开辟好空间，避免底层数组频繁申请内存
	var fingerprint = make([]byte, 0, 65535)
	var tmp = make([]byte, 256)
	// 存储读取的字节数
	var num int
	var szBan string
	var szSvcName string

	// 这里设置成6秒是因为超时的时候会重新尝试5次，

	readTimeout := 2 * time.Second

	// 设置读取的超时时间为6s
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	for {
		// Read是阻塞的
		n, err := conn.Read(tmp)
		if err != nil {
			// 虽然数据读取错误，但是端口仍然是open的
			// fmt.Println(err)
			if err != io.EOF {
				dwSvc = SOCKET_READ_TIMEOUT
				// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			}
			break
		}

		if n > 0 {
			num += n
			fingerprint = append(fingerprint, tmp[:n]...)
		} else {
			// 虽然没有读取到数据，但是端口仍然是open的
			// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			break
		}
	}
	// 服务识别
	if num > 0 {
		dwSvc = ComparePackets(fingerprint, num, &szBan, &szSvcName)
		//if len(szBan) > 15 {
		//	szBan = szBan[:15]
		//}
		if dwSvc > UNKNOWN_PORT && dwSvc < SOCKET_CONNECT_FAILED {
			//even.WorkingEvent = "found"
			//fmt.Printf("szSvcName:%v\n", szSvcName)
			if szSvcName == "ssl/tls" || szSvcName == "http" {
				rst := Ghttp.GetHttpTitle(ip, Ghttp.HTTPorHTTPS, int(port))
				result.WorkingEvent = rst
				cert, err0 := Ghttp.GetCert(ip, int(port))
				if err0 != nil {
					cert = ""
				}
				result.Info.Cert = cert
			} else {
				result.Info.Banner = strings.TrimSpace(szBan)
			}
			result.Info.Service = szSvcName
			result.Time = time.Now().Format("2006-01-02 15:04:05")
			// fmt.Printf("Discovered open port\t%d\ton\t%s\t\t%s\t\t%s\n", port, ip, szSvcName, strings.TrimSpace(szBan))
			//return dwSvc, even
		}
	}

	return dwSvc, result
}
