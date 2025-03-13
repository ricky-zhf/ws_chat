package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// 写入超时时间
	writeWait = 10 * time.Second

	// 读取超时时间
	pongWait = 60 * time.Second

	// Ping周期，必须小于pongWait
	pingPeriod = (pongWait * 9) / 10

	// 最大消息大小
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// 允许所有来源的连接
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// 连接表示WebSocket的客户端连接
type Client struct {
	hub *Hub

	// WebSocket连接
	conn *websocket.Conn

	// 发送消息的缓冲通道
	send chan []byte

	// 客户端ID
	id string

	// 用户名
	username string

	// 会话ID
	sessionID string
}

// 消息中心
type Hub struct {
	// 注册的客户端
	clients map[*Client]bool

	// 从客户端发送的消息
	broadcast chan []byte

	// 注册请求
	register chan *Client

	// 注销请求
	unregister chan *Client
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

// 读取消息的goroutine
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		// 结束会话
		if c.sessionID != "" {
			if err := endSession(c.sessionID); err != nil {
				log.Printf("结束会话失败: %v", err)
			}
		}
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))

		// 解析收到的消息
		var data map[string]interface{}
		if err := json.Unmarshal(message, &data); err == nil {
			// 检查是否是系统消息（如退出消息）
			if msgType, ok := data["type"].(string); ok && msgType == "system" {
				// 是系统消息，例如退出通知
				if content, ok := data["content"].(string); ok {
					// 广播系统消息
					data["sender"] = c.id
					data["username"] = c.username
					data["timestamp"] = time.Now().Format(time.RFC3339)

					// 保存系统消息到数据库
					_, err := saveMessage(content, c.id, c.username, c.sessionID)
					if err != nil {
						log.Printf("保存系统消息失败: %v", err)
					}

					if newMessage, err := json.Marshal(data); err == nil {
						c.hub.broadcast <- newMessage
					}
				}
			} else if msgType, ok := data["type"].(string); ok && msgType == "chat" {
				// 普通聊天消息的处理逻辑
				// 如果是聊天消息，保存到数据库
				if content, ok := data["content"].(string); ok && content != "" {
					// 保存消息到数据库
					_, err := saveMessage(content, c.id, c.username, c.sessionID)
					if err != nil {
						log.Printf("保存消息失败: %v", err)
					}

					// 添加发送者信息
					data["sender"] = c.id
					data["username"] = c.username
					data["timestamp"] = time.Now().Format(time.RFC3339)

					// 重新序列化消息
					if newMessage, err := json.Marshal(data); err == nil {
						c.hub.broadcast <- newMessage
					}
				}
			} else if msgType, ok := data["type"].(string); ok && msgType == "history" {
				// 处理历史消息
				if content, ok := data["content"].(string); ok && content != "" {
					// 保存消息到数据库
					_, err := saveMessage(content, c.id, c.username, c.sessionID)
					if err != nil {
						log.Printf("保存历史消息失败: %v", err)
					}

					// 添加发送者信息
					data["sender"] = c.id
					data["username"] = c.username
					data["timestamp"] = time.Now().Format(time.RFC3339)

					// 重新序列化消息
					if historyMsg, err := json.Marshal(data); err == nil {
						c.hub.broadcast <- historyMsg
					}
				}
			}
		} else {
			// 如果不是JSON格式，创建一个新的消息
			content := string(message)
			// 保存消息到数据库
			_, err := saveMessage(content, c.id, c.username, c.sessionID)
			if err != nil {
				log.Printf("保存消息失败: %v", err)
			}

			newMessage, _ := json.Marshal(map[string]interface{}{
				"type":      "chat",
				"content":   content,
				"sender":    c.id,
				"username":  c.username,
				"timestamp": time.Now().Format(time.RFC3339),
			})
			c.hub.broadcast <- newMessage
		}
	}
}

// 写入消息的goroutine
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// 中心已关闭该通道
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// 添加队列中的消息
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// 处理WebSocket请求
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	// 为客户端生成唯一ID
	clientID := generateClientID()

	client := &Client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, 256),
		id:   clientID,
	}
	client.hub.register <- client

	// 发送客户端ID到前端
	idMsg, _ := json.Marshal(map[string]string{
		"type": "id",
		"id":   clientID,
	})
	client.send <- idMsg

	// 启动goroutines来处理读写
	go client.writePump()
	go client.readPump()
}

// 生成唯一的客户端ID
func generateClientID() string {
	now := time.Now().UnixNano()
	random := rand.Intn(1000)
	return fmt.Sprintf("user_%d_%d", now, random)
}
