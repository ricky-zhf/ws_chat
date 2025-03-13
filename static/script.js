let socket;
let isConnected = false;
let clientId = null; // 存储客户端ID

const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const messagesContainer = document.getElementById('chat-messages');
const statusElement = document.getElementById('status');

// 连接WebSocket
function connectWebSocket() {
    // 确定WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `≈s`;

    // 创建WebSocket连接
    socket = new WebSocket(wsUrl);

    // 连接打开时
    socket.onopen = function () {
        isConnected = true;
        messageInput.disabled = false;
        sendButton.disabled = false;
        statusElement.textContent = '已连接';
        statusElement.classList.add('connected');
        statusElement.classList.remove('disconnected');
        console.log("WebSocket连接已建立");
    };

    // 接收消息
    socket.onmessage = function (event) {
        const message = JSON.parse(event.data);

        // 处理不同类型的消息
        if (message.type === 'id') {
            // 保存服务器分配的客户端ID
            clientId = message.id;
            console.log("获得客户端ID:", clientId);

            // 更新标题，添加唯一标识
            document.title = `实时对话 - ${clientId.substring(0, 8)}`;

            // 在状态栏显示ID
            statusElement.textContent = `已连接 (ID: ${clientId.substring(0, 8)})`;
        }
        else if (message.type === 'system') {
            // 处理系统消息
            statusElement.textContent = `已连接 (ID: ${clientId.substring(0, 8)}) - ${message.clients}人在线`;
        }
        else if (message.type === 'chat') {
            // 处理聊天消息
            const isSelf = message.sender === clientId;
            displayMessage(message.content, isSelf ? 'self' : 'other', message.sender);
        }
    };

    // 连接关闭时
    socket.onclose = function () {
        isConnected = false;
        messageInput.disabled = true;
        sendButton.disabled = true;
        statusElement.textContent = '已断开';
        statusElement.classList.add('disconnected');
        statusElement.classList.remove('connected');
        console.log("WebSocket连接已关闭");

        // 尝试重新连接
        setTimeout(connectWebSocket, 3000);
    };

    // 发生错误时
    socket.onerror = function (error) {
        console.error("WebSocket发生错误:", error);
    };
}

// 显示消息
function displayMessage(content, type, senderId) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message', type);

    const avatarElement = document.createElement('div');
    avatarElement.classList.add('message-avatar');

    // 显示简短的用户ID
    const shortId = senderId ? senderId.substring(0, 4) : (type === 'self' ? '我' : '他');
    avatarElement.textContent = shortId;

    const contentElement = document.createElement('div');
    contentElement.classList.add('message-content');
    contentElement.textContent = content;

    messageElement.appendChild(avatarElement);
    messageElement.appendChild(contentElement);

    messagesContainer.appendChild(messageElement);

    // 滚动到底部
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// 发送消息
function sendMessage() {
    const content = messageInput.value.trim();
    if (content && isConnected) {
        const message = {
            type: 'chat',
            content: content
            // 不需要在这里设置sender，服务器会添加
        };

        socket.send(JSON.stringify(message));
        messageInput.value = '';
    }
}

// 设置事件监听器
sendButton.addEventListener('click', sendMessage);

messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// 初始化
connectWebSocket(); 