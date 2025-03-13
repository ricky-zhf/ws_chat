package main

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User 用户模型
type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username  string             `bson:"username" json:"username"`
	Password  string             `bson:"password" json:"-"` // 密码不会在JSON中返回
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// Message 消息模型
type Message struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Content   string             `bson:"content" json:"content"`
	SenderID  string             `bson:"sender_id" json:"sender_id"`
	Username  string             `bson:"username" json:"username"`
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	SessionID string             `bson:"session_id" json:"session_id"`
}

// Session 会话模型
type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	StartTime time.Time          `bson:"start_time" json:"start_time"`
	EndTime   *time.Time         `bson:"end_time" json:"end_time"`
	Users     []string           `bson:"users" json:"users"` // 用户ID列表
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse 认证响应
type AuthResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	UserID   string `json:"user_id"`
}
