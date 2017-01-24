package main

import (
	"crypto/sha1"
	"log"
	"math/rand"
	"os"
	"time"
	
	"golang.org/x/crypto/pbkdf2"
	
	"github.com/urfave/cli"
	kcp "github.com/xtaci/kcp-go"
	"sync"
	"encoding/binary"
	"net"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "highway-udp"
	
	portMap map[uint16]*kcp.UDPSession
	localUDPAddr *net.UDPAddr
	localUDPConn map[uint16]*net.UDPConn
	globalMutex sync.Mutex
)


func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func setPortMap(port uint16, conn *kcp.UDPSession) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	
	portMap[port] = conn
}

func getPortKCP(port uint16) *kcp.UDPSession {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	conn := portMap[port]
	return conn
}


func writeLocalUDP(port uint16, data []byte) {
	globalMutex.Lock()
	
	conn, ok := localUDPConn[port]
	if !ok {
		raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:" + string(port))
		checkError(err)
		conn, err = net.DialUDP("udp", localUDPAddr, raddr);
		checkError(err)
		localUDPConn[port] = conn
	}
	
	globalMutex.Unlock()
	
	_, err := conn.Write(data)
	checkError(err)
}

func handleLocalRead(config *Config) {
	listener, err := net.ListenUDP("udp", localUDPAddr)
	checkError(err)

	buf := make([]byte, config.MTU)

	for {
		size, addr, err := listener.ReadFromUDP(buf[2:])
		checkError(err)

		port := uint16(addr.Port)
		binary.LittleEndian.PutUint16(buf[:2], port)

		rConn := getPortKCP(port)
		if rConn != nil {
			rConn.Write(buf[:size+2])
		}
	}
}

func handleRemoteRead(conn *kcp.UDPSession, config *Config) {
	buf := make([]byte, config.MTU)

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		size, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return
		}
		
		targetPort := binary.LittleEndian.Uint16(buf[:2])
		setPortMap(targetPort, conn)
		writeLocalUDP(targetPort, buf[2:size])
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "SELFBUILD" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "server(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:	"listen,l",
			Value: ":8096",
			Usage: "kcp server listen address",
		},
		cli.StringFlag{
			Name:	"listenlocal,ll",
			Value: ":8097",
			Usage: "local udp listen address",
		},
		cli.StringFlag{
			Name:	"target, t",
			Value: "127.0.0.1:12948",
			Usage: "target server address",
		},
		cli.StringFlag{
			Name:	 "key",
			Value:	"it's a secrect",
			Usage:	"pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:	"crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, none",
		},
		cli.StringFlag{
			Name:	"mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal",
		},
		cli.IntFlag{
			Name:	"mtu",
			Value: 1448,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:	"sndwnd",
			Value: 2048,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:	"rcvwnd",
			Value: 2048,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:	"datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:	"parityshard,ps",
			Value: 1,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.BoolFlag{
			Name:	 "acknodelay",
			Usage:	"flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "nodelay",
			Value:	0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "interval",
			Value:	40,
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "resend",
			Value:	0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "nc",
			Value:	0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "sockbuf",
			Value:	4194304, // socket buffer size in bytes
			Hidden: true,
		},
		cli.IntFlag{
			Name:	 "keepalive",
			Value:	10, // nat keepalive interval in seconds
			Hidden: true,
		},
		cli.StringFlag{
			Name:	"c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.Listen = c.String("listen")
		config.ListenLocal = c.String("listenlocal")
		config.Target = c.String("target")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.KeepAlive = c.Int("keepalive")
		
		if c.String("c") != "" {
			//Now only support json config file
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}
		
		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 20, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}
		
		log.Println("version:", VERSION)
		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}
	
		bufPool.New = func() interface{} {
			return make([]byte, config.MTU)
		}
		
		lis, err := kcp.ListenWithOptions(config.Listen, block, config.DataShard, config.ParityShard)
		checkError(err)
		log.Println("listening on:", lis.Addr())
		log.Println("target:", config.Target)
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		
		if err := lis.SetReadBuffer(config.SockBuf); err != nil {
			log.Println("SetReadBuffer:", err)
		}
		if err := lis.SetWriteBuffer(config.SockBuf); err != nil {
			log.Println("SetWriteBuffer:", err)
		}
		
		for {
			if conn, err := lis.AcceptKCP(); err == nil {
				log.Println("remote address:", conn.RemoteAddr())
				conn.SetStreamMode(false)
				conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
				conn.SetMtu(config.MTU)
				conn.SetWindowSize(config.SndWnd, config.RcvWnd)
				conn.SetACKNoDelay(config.AckNodelay)
				conn.SetKeepAlive(config.KeepAlive)
				conn.SetReadBuffer(config.SockBuf)
				conn.SetWriteBuffer(config.SockBuf)
				
				go handleRemoteRead(conn, &config)
			} else {
				log.Printf("%+v", err)
			}
		}
	}
	myApp.Run(os.Args)
}
