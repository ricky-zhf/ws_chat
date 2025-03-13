package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var jwtSecret = []byte("your_jwt_secret_key")

// Claims 定义JWT的负载内容
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// 生成JWT令牌
func generateToken(userID, username string) (string, error) {
	expireTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   "user_token",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// 验证JWT令牌
func validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// 处理注册请求
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	user, err := createUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := generateToken(user.ID.Hex(), user.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token:    token,
		Username: user.Username,
		UserID:   user.ID.Hex(),
	})
}

// 处理登录请求
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := authenticateUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token, err := generateToken(user.ID.Hex(), user.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token:    token,
		Username: user.Username,
		UserID:   user.ID.Hex(),
	})
}

// 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 去掉Bearer前缀
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// 将用户信息添加到请求上下文
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-User-Name", claims.Username)

		next(w, r)
	}
}

// 首页处理
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
	http.ServeFile(w, r, "static/login.html")
}

// 处理WebSocket请求，支持通过会话ID连接
func serveWsWithAuth(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// 从URL参数获取token
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 验证token
	claims, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 获取会话ID参数
	sessionIDStr := r.URL.Query().Get("sessionId")

	var sessionID string

	// 如果指定了会话ID，验证该会话
	if sessionIDStr != "" {
		// 验证会话是否存在且用户有权限访问
		sessionObjID, err := primitive.ObjectIDFromHex(sessionIDStr)
		if err != nil {
			log.Printf("无效的会话ID: %v", err)
			http.Error(w, "Invalid session ID", http.StatusBadRequest)
			return
		}

		// 检查会话是否存在
		var session Session
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = sessionsCol.FindOne(ctx, bson.M{"_id": sessionObjID}).Decode(&session)
		if err != nil {
			log.Printf("查找会话失败: %v", err)
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// 检查用户是否是会话的参与者
		isParticipant := false
		for _, uid := range session.Users {
			if uid == claims.UserID {
				isParticipant = true
				break
			}
		}

		if !isParticipant {
			log.Printf("用户 %s 尝试访问未授权的会话 %s", claims.Username, sessionIDStr)
			http.Error(w, "Unauthorized access to session", http.StatusForbidden)
			return
		}

		sessionID = sessionIDStr
		log.Printf("用户 %s 加入了会话 %s", claims.Username, sessionID)
	} else {
		// 如果没有指定会话ID，创建新会话
		session, err := createSession([]string{claims.UserID})
		if err != nil {
			log.Printf("创建会话失败: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		sessionID = session.ID.Hex()
		log.Printf("为用户 %s 创建了新会话 %s", claims.Username, sessionID)
	}

	// 升级连接为WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	// 创建客户端
	client := &Client{
		hub:       hub,
		conn:      conn,
		send:      make(chan []byte, 256),
		id:        claims.UserID,
		username:  claims.Username,
		sessionID: sessionID,
	}
	client.hub.register <- client

	// 发送客户端信息
	idMsg, _ := json.Marshal(map[string]interface{}{
		"type":      "id",
		"id":        claims.UserID,
		"username":  claims.Username,
		"sessionID": sessionID,
	})
	client.send <- idMsg

	// 加载历史消息
	go func() {
		time.Sleep(500 * time.Millisecond)

		messages, err := getSessionMessages(sessionID)
		if err != nil {
			log.Printf("获取历史消息失败: %v", err)
			return
		}

		if len(messages) > 0 {
			historyStartMsg, _ := json.Marshal(map[string]interface{}{
				"type":    "system",
				"content": "正在加载历史消息...",
			})
			client.send <- historyStartMsg

			for _, msg := range messages {
				historyMsg, _ := json.Marshal(map[string]interface{}{
					"type":      "history",
					"content":   msg.Content,
					"sender":    msg.SenderID,
					"username":  msg.Username,
					"timestamp": msg.Timestamp.Format(time.RFC3339),
				})
				client.send <- historyMsg
				time.Sleep(20 * time.Millisecond)
			}

			historyEndMsg, _ := json.Marshal(map[string]interface{}{
				"type":    "system",
				"content": fmt.Sprintf("已加载 %d 条历史消息", len(messages)),
			})
			client.send <- historyEndMsg
		}
	}()

	// 启动goroutines来处理读写
	go client.writePump()
	go client.readPump()
}

// 获取用户的会话列表
func handleGetUserSessions(w http.ResponseWriter, r *http.Request) {
	// 从请求头获取用户信息
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 获取用户的所有会话
	sessions, err := getUserSessionsWithDetails(userID)
	if err != nil {
		log.Printf("获取用户会话失败: %v", err)
		http.Error(w, "Failed to get sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// 搜索用户
func handleSearchUsers(w http.ResponseWriter, r *http.Request) {
	// 获取当前用户ID
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 获取查询参数
	query := r.URL.Query().Get("q")
	if query == "" {
		// 如果查询为空，返回空结果
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	// 搜索用户
	users, err := searchUsers(query, userID)
	if err != nil {
		log.Printf("搜索用户失败: %v", err)
		http.Error(w, "Failed to search users", http.StatusInternalServerError)
		return
	}

	// 返回结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// 创建或获取与指定用户的会话
func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	// 获取当前用户ID
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 只接受POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.UserID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// 不能与自己创建会话
	if req.UserID == userID {
		http.Error(w, "Cannot create session with yourself", http.StatusBadRequest)
		return
	}

	// 获取或创建会话
	session, err := getOrCreateSessionBetweenUsers(userID, req.UserID)
	if err != nil {
		log.Printf("创建会话失败: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 获取对方用户信息
	otherUserObjID, _ := primitive.ObjectIDFromHex(req.UserID)
	var otherUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = usersCol.FindOne(ctx, bson.M{"_id": otherUserObjID}).Decode(&otherUser)
	if err != nil {
		log.Printf("获取用户信息失败: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// 构建响应
	response := struct {
		SessionID string    `json:"session_id"`
		OtherUser User      `json:"other_user"`
		StartTime time.Time `json:"start_time"`
	}{
		SessionID: session.ID.Hex(),
		OtherUser: otherUser,
		StartTime: session.StartTime,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
