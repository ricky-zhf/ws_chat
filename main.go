package main

import (
	"flag"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":8080", "http service address")

func main() {
	flag.Parse()

	// 初始化数据库
	if err := initDatabase(); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer closeDatabase()

	hub := newHub()
	go hub.run()

	// 静态文件服务
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 认证相关路由
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)

	// 会话相关路由
	http.HandleFunc("/api/sessions", authMiddleware(handleGetUserSessions))      // 获取用户的会话列表
	http.HandleFunc("/api/sessions/create", authMiddleware(handleCreateSession)) // 创建新会话

	// 用户相关路由
	http.HandleFunc("/api/users/search", authMiddleware(handleSearchUsers)) // 搜索用户

	// WebSocket端点
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWsWithAuth(hub, w, r)
	})

	// 首页路由
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})

	// 启动服务器
	log.Printf("Starting server on %s", *addr)
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
