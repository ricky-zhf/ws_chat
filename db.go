package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	client      *mongo.Client
	db          *mongo.Database
	usersCol    *mongo.Collection
	messagesCol *mongo.Collection
	sessionsCol *mongo.Collection
)

// 初始化数据库连接
func initDatabase() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	clientOptions := options.Client().ApplyURI("mongodb://127.0.0.1:27017")
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("无法连接MongoDB: %v", err)
	}

	// 检查连接
	err = client.Ping(ctx, nil)
	if err != nil {
		return fmt.Errorf("无法ping MongoDB: %v", err)
	}

	log.Println("已连接到MongoDB")

	// 设置集合
	db = client.Database("chat_app")
	usersCol = db.Collection("users")
	messagesCol = db.Collection("messages")
	sessionsCol = db.Collection("sessions")

	// 创建用户名唯一索引
	_, err = usersCol.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "username", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		return fmt.Errorf("创建索引失败: %v", err)
	}

	return nil
}

// 关闭数据库连接
func closeDatabase() {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Disconnect(ctx); err != nil {
			log.Printf("断开MongoDB连接时出错: %v", err)
		}
		log.Println("MongoDB连接已关闭")
	}
}

// 创建新用户
func createUser(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 检查用户名是否已存在
	var existingUser User
	err := usersCol.FindOne(ctx, bson.M{"username": username}).Decode(&existingUser)
	if err == nil {
		return nil, fmt.Errorf("用户名已存在")
	} else if err != mongo.ErrNoDocuments {
		return nil, fmt.Errorf("查询用户失败: %v", err)
	}

	// 哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("密码哈希失败: %v", err)
	}

	// 创建用户
	user := &User{
		Username:  username,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	result, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("创建用户失败: %v", err)
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return user, nil
}

// 验证用户
func authenticateUser(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := usersCol.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("用户名或密码错误")
		}
		return nil, fmt.Errorf("查询用户失败: %v", err)
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("用户名或密码错误")
	}

	return &user, nil
}

// 创建新会话
func createSession(userIDs []string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session := &Session{
		StartTime: time.Now(),
		Users:     userIDs,
	}

	result, err := sessionsCol.InsertOne(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %v", err)
	}

	session.ID = result.InsertedID.(primitive.ObjectID)
	return session, nil
}

// 结束会话
func endSession(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id, err := primitive.ObjectIDFromHex(sessionID)
	if err != nil {
		return fmt.Errorf("无效的会话ID: %v", err)
	}

	now := time.Now()
	_, err = sessionsCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"end_time": now}},
	)
	if err != nil {
		return fmt.Errorf("更新会话失败: %v", err)
	}

	return nil
}

// 保存消息
func saveMessage(content, senderID, username, sessionID string) (*Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	message := &Message{
		Content:   content,
		SenderID:  senderID,
		Username:  username,
		Timestamp: time.Now(),
		SessionID: sessionID,
	}

	result, err := messagesCol.InsertOne(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("保存消息失败: %v", err)
	}

	message.ID = result.InsertedID.(primitive.ObjectID)
	return message, nil
}

// 获取会话消息
func getSessionMessages(sessionID string) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"session_id": sessionID}
	options := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := messagesCol.Find(ctx, filter, options)
	if err != nil {
		return nil, fmt.Errorf("查询消息失败: %v", err)
	}
	defer cursor.Close(ctx)

	var messages []Message
	if err = cursor.All(ctx, &messages); err != nil {
		return nil, fmt.Errorf("解析消息失败: %v", err)
	}

	return messages, nil
}

// 根据用户名获取用户
func getUserByUsername(username string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := usersCol.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %v", err)
	}

	return &user, nil
}

// 查找两个用户之间的会话
func findSessionBetweenUsers(userID1, userID2 string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 构建查询 - 查找包含这两个用户的会话，并且没有结束时间（活跃会话）
	filter := bson.M{
		"users":    bson.M{"$all": []string{userID1, userID2}},
		"end_time": nil, // 未结束的会话
	}

	var session Session
	err := sessionsCol.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // 没有找到会话，但不是错误
		}
		return nil, fmt.Errorf("查询会话失败: %v", err)
	}

	return &session, nil
}

// 创建或获取两个用户之间的会话
func getOrCreateSessionBetweenUsers(userID1, userID2 string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 尝试查找现有会话
	filter := bson.M{
		"users":    bson.M{"$all": []string{userID1, userID2}},
		"end_time": nil, // 未结束的会话
	}

	var session Session
	err := sessionsCol.FindOne(ctx, filter).Decode(&session)

	if err == nil {
		// 找到会话，返回
		return &session, nil
	}

	if err != mongo.ErrNoDocuments {
		// 发生了除"未找到文档"外的错误
		return nil, fmt.Errorf("查询会话失败: %v", err)
	}

	// 没有找到现有会话，创建新会话
	newSession := Session{
		StartTime: time.Now(),
		Users:     []string{userID1, userID2},
	}

	result, err := sessionsCol.InsertOne(ctx, newSession)
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %v", err)
	}

	// 获取插入的ID
	newSession.ID = result.InsertedID.(primitive.ObjectID)

	return &newSession, nil
}

// 获取用户的所有活跃会话
func getUserActiveSessions(userID string) ([]Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"users":    userID,
		"end_time": nil,
	}

	cursor, err := sessionsCol.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("查询用户会话失败: %v", err)
	}
	defer cursor.Close(ctx)

	var sessions []Session
	if err = cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("解析会话失败: %v", err)
	}

	return sessions, nil
}

// SessionWithDetails 包含会话信息和最后一条消息
type SessionWithDetails struct {
	ID           string    `json:"id"`
	StartTime    time.Time `json:"start_time"`
	OtherUser    User      `json:"other_user"`
	LastMessage  Message   `json:"last_message,omitempty"`
	LastActivity time.Time `json:"last_activity"`
}

// 获取用户的所有会话及详情
func getUserSessionsWithDetails(userID string) ([]SessionWithDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 查找用户参与的所有会话
	filter := bson.M{
		"users": userID,
	}

	cursor, err := sessionsCol.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("查询会话失败: %v", err)
	}
	defer cursor.Close(ctx)

	var sessions []Session
	if err = cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("解析会话失败: %v", err)
	}

	// 获取每个会话的详情
	var result []SessionWithDetails
	for _, session := range sessions {
		sessionDetails := SessionWithDetails{
			ID:        session.ID.Hex(),
			StartTime: session.StartTime,
		}

		// 找出对话中的另一个用户
		var otherUserID string
		for _, uid := range session.Users {
			if uid != userID {
				otherUserID = uid
				break
			}
		}

		// 获取另一个用户的信息
		if otherUserID != "" {
			otherUserObjID, _ := primitive.ObjectIDFromHex(otherUserID)
			var otherUser User
			err := usersCol.FindOne(ctx, bson.M{"_id": otherUserObjID}).Decode(&otherUser)
			if err == nil {
				sessionDetails.OtherUser = otherUser
			}
		}

		// 获取最后一条消息
		var lastMessage Message
		err := messagesCol.FindOne(
			ctx,
			bson.M{"session_id": session.ID.Hex()},
			options.FindOne().SetSort(bson.M{"timestamp": -1}),
		).Decode(&lastMessage)

		if err == nil {
			sessionDetails.LastMessage = lastMessage
			sessionDetails.LastActivity = lastMessage.Timestamp
		} else {
			// 如果没有消息，使用会话开始时间
			sessionDetails.LastActivity = session.StartTime
		}

		result = append(result, sessionDetails)
	}

	// 按最后活动时间排序（从新到旧）
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastActivity.After(result[j].LastActivity)
	})

	return result, nil
}

// 搜索用户
func searchUsers(query string, excludeUserID string) ([]User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 将用户ID转换为ObjectID
	var excludeObjID primitive.ObjectID
	var err error
	if excludeUserID != "" {
		excludeObjID, err = primitive.ObjectIDFromHex(excludeUserID)
		if err != nil {
			return nil, fmt.Errorf("无效的用户ID: %v", err)
		}
	}

	// 创建正则表达式查询（不区分大小写）
	regexQuery := bson.M{"username": primitive.Regex{
		Pattern: query,
		Options: "i",
	}}

	// 排除当前用户
	filter := bson.M{
		"$and": []bson.M{
			regexQuery,
			{"_id": bson.M{"$ne": excludeObjID}},
		},
	}

	// 限制结果数量和投影（不返回密码字段）
	findOptions := options.Find().
		SetLimit(10).
		SetProjection(bson.M{"password": 0})

	cursor, err := usersCol.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, fmt.Errorf("搜索用户失败: %v", err)
	}
	defer cursor.Close(ctx)

	var users []User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("解析用户结果失败: %v", err)
	}

	return users, nil
}
