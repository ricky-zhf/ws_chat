package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/rand"
	"net/http"
	"time"
)

var addr = flag.String("addr", ":8080", "http service address")

// 初始化随机数种子
func init() {
	rand.Seed(time.Now().UnixNano())
}

// 随机数响应结构
type RandomResponse struct {
	Number int    `json:"number"`
	Time   string `json:"time"`
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "static/index.html")
}

// 随机数生成处理函数
func generateRandom(w http.ResponseWriter, r *http.Request) {
	// 设置CORS头，允许所有来源的请求
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// 生成1-10000之间的随机数
	randomNumber := rand.Intn(10000) + 1

	// 创建响应
	response := RandomResponse{
		Number: randomNumber,
		Time:   time.Now().Format(time.RFC3339),
	}

	// 序列化为JSON并返回
	json.NewEncoder(w).Encode(response)

	log.Printf("生成随机数: %d", randomNumber)
}

func main() {
	flag.Parse()
	hub := newHub()
	go hub.run()

	// 提供静态文件
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 处理WebSocket连接
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	// 添加随机数生成端点
	http.HandleFunc("/random", generateRandom)

	// 提供主页
	http.HandleFunc("/", serveHome)

	// 启动服务器
	log.Printf("Starting server on %s", *addr)
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
