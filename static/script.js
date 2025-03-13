let socket;
let isConnected = false;
let clientId = null; // 存储客户端ID
let sessionId = null; // 存储会话ID
let currentSessionId = null;
let sessions = [];

const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const messagesContainer = document.getElementById('chat-messages');
const statusElement = document.getElementById('status');
const logoutBtn = document.getElementById('logout-btn');
const usernameDisplay = document.getElementById('username-display');
const sessionsListElem = document.getElementById('sessions-list');
const chatTitle = document.getElementById('chat-title');
const searchInput = document.getElementById('search-input');
const searchBtn = document.getElementById('search-btn');
const searchResultsContainer = document.getElementById('search-results');

// 初始化应用
function initApp() {
    // 获取保存的认证信息
    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');

    if (!token) {
        window.location.href = '/';
        return;
    }

    // 显示用户名
    if (username) {
        usernameDisplay.textContent = username;
    }

    // 加载会话列表
    loadSessionsList();
}

// 加载用户的会话列表
async function loadSessionsList() {
    try {
        const token = localStorage.getItem('token');

        const response = await fetch('/api/sessions', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('获取会话列表失败');
        }

        const data = await response.json();
        sessions = data;

        renderSessionsList();

        // 如果有会话，默认打开第一个
        if (sessions.length > 0) {
            openSession(sessions[0].id);
        } else {
            // 没有会话，显示空状态
            messagesContainer.innerHTML = '<div class="empty-state">没有聊天记录</div>';
            chatTitle.textContent = '无会话';
        }
    } catch (error) {
        console.error('加载会话列表失败:', error);
        sessionsListElem.innerHTML = '<div class="error-loading">加载会话列表失败</div>';
    }
}

// 渲染会话列表
function renderSessionsList() {
    sessionsListElem.innerHTML = '';

    if (sessions.length === 0) {
        sessionsListElem.innerHTML = '<div class="no-sessions">暂无会话</div>';
        return;
    }

    sessions.forEach(session => {
        const sessionItem = document.createElement('div');
        sessionItem.classList.add('session-item');
        if (session.id === currentSessionId) {
            sessionItem.classList.add('active');
        }

        const avatarChar = session.other_user.username.charAt(session.other_user.username.length - 1);

        // 构建预览文本
        let previewText = '';
        if (session.last_message && session.last_message.content) {
            previewText = session.last_message.content;
            if (previewText.length > 20) {
                previewText = previewText.substring(0, 20) + '...';
            }
        } else {
            previewText = '没有消息';
        }

        // 格式化时间
        const lastTime = session.last_activity ? new Date(session.last_activity) : new Date(session.start_time);
        const timeFormatted = formatMessageTime(lastTime);

        sessionItem.innerHTML = `
            <div class="session-avatar">${avatarChar}</div>
            <div class="session-info">
                <div class="session-name">${session.other_user.username}</div>
                <div class="session-preview">${previewText}</div>
                <div class="session-time">${timeFormatted}</div>
            </div>
        `;

        sessionItem.addEventListener('click', () => openSession(session.id));
        sessionsListElem.appendChild(sessionItem);
    });
}

// 格式化消息时间
function formatMessageTime(date) {
    const now = new Date();
    const diff = now - date;
    const diffDays = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
        // 今天，显示时间
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays === 1) {
        // 昨天
        return '昨天';
    } else if (diffDays < 7) {
        // 一周内，显示周几
        const days = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
        return days[date.getDay()];
    } else {
        // 超过一周，显示日期
        return date.toLocaleDateString();
    }
}

// 打开会话
function openSession(sessionId) {
    // 关闭之前的WebSocket连接
    if (socket && isConnected) {
        socket.close();
    }

    // 保存当前会话ID
    currentSessionId = sessionId;

    // 清空消息容器
    messagesContainer.innerHTML = '';

    // 更新UI状态
    const currentSession = sessions.find(s => s.id === sessionId);
    if (currentSession) {
        chatTitle.textContent = `与 ${currentSession.other_user.username} 的对话`;

        // 高亮当前会话
        const sessionItems = document.querySelectorAll('.session-item');
        sessionItems.forEach(item => {
            item.classList.remove('active');
        });

        const activeItem = Array.from(sessionItems).find(
            item => item.querySelector('.session-name').textContent === currentSession.other_user.username
        );
        if (activeItem) {
            activeItem.classList.add('active');
        }
    }

    // 连接WebSocket，指定目标会话
    connectWebSocket(sessionId);
}

// 连接WebSocket，修改为接收会话ID参数
function connectWebSocket(sessionId) {
    const token = localStorage.getItem('token');

    if (!token) {
        console.error("未找到token，请先登录");
        window.location.href = '/';
        return;
    }

    // 构建WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    let wsUrl = `${protocol}//${host}/ws?token=${encodeURIComponent(token)}`;

    // 如果指定了会话ID，添加到URL
    if (sessionId) {
        wsUrl += `&sessionId=${encodeURIComponent(sessionId)}`;
    }

    console.log("正在连接WebSocket:", wsUrl);

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
        let message;
        try {
            message = JSON.parse(event.data);
        } catch (error) {
            console.error("解析消息失败:", error, event.data);
            return; // 跳过无法解析的消息
        }

        // 处理不同类型的消息
        if (message.type === 'id') {
            clientId = message.id;
            sessionId = message.sessionID;
            console.log("获得客户端ID:", clientId, "会话ID:", sessionId);

            // 更新标题
            document.title = `实时对话 - ${message.username}`;

            // 在状态栏显示信息
            statusElement.textContent = `已连接 (${message.username})`;
        }
        else if (message.type === 'system') {
            // 显示系统消息
            displaySystemMessage(message.content);
        }
        else if (message.type === 'history') {
            // 处理历史消息，传递timestamp参数
            const isSelf = message.sender === clientId;
            displayMessage(
                message.content,
                isSelf ? 'self' : 'other',
                message.sender,
                message.username,
                true,
                message.timestamp // 添加timestamp参数
            );
        }
        else if (message.type === 'chat') {
            // 处理新聊天消息，传递timestamp参数
            const isSelf = message.sender === clientId;
            displayMessage(
                message.content,
                isSelf ? 'self' : 'other',
                message.sender,
                message.username,
                false,
                message.timestamp // 添加timestamp参数
            );

            // 更新会话列表中的预览
            updateSessionPreview(sessionId, message.content);
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
    };

    // 发生错误时
    socket.onerror = function (error) {
        console.error("WebSocket发生错误:", error);
    };
}

// 更新会话列表中的预览
function updateSessionPreview(sessionId, content) {
    // 查找对应的会话
    const sessionIndex = sessions.findIndex(s => s.id === sessionId);
    if (sessionIndex >= 0) {
        // 更新最后消息内容和时间
        sessions[sessionIndex].last_message = {
            content: content,
            timestamp: new Date().toISOString()
        };
        sessions[sessionIndex].last_activity = new Date().toISOString();

        // 将该会话移到顶部
        const session = sessions.splice(sessionIndex, 1)[0];
        sessions.unshift(session);

        // 重新渲染会话列表
        renderSessionsList();
    }
}

// 显示系统消息
function displaySystemMessage(content) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message', 'system');

    const contentElement = document.createElement('div');
    contentElement.classList.add('system-content');
    contentElement.textContent = content;

    messageElement.appendChild(contentElement);
    messagesContainer.appendChild(messageElement);

    // 滚动到底部
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// 改进显示消息函数，支持用户名和历史消息标记
function displayMessage(content, type, senderId, username, isHistory, timestamp) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message', type);

    // 如果是历史消息，添加历史样式
    if (isHistory) {
        messageElement.classList.add('history');
    }

    const avatarElement = document.createElement('div');
    avatarElement.classList.add('message-avatar');

    // 显示用户名最后一个字符
    let displayChar;
    if (type === 'self') {
        const myUsername = localStorage.getItem('username') || '我';
        displayChar = myUsername.charAt(myUsername.length - 1);
    } else {
        displayChar = username ? username.charAt(username.length - 1) : '他';
    }

    avatarElement.textContent = displayChar;

    const contentElement = document.createElement('div');
    contentElement.classList.add('message-content');
    contentElement.textContent = content;

    // 如果是历史消息，可以添加时间戳
    if (isHistory && timestamp) {
        const timeElement = document.createElement('div');
        timeElement.classList.add('message-time');
        timeElement.textContent = new Date(timestamp).toLocaleString();
        contentElement.appendChild(timeElement);
    }

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
        };

        socket.send(JSON.stringify(message));
        messageInput.value = '';
    }
}

// 退出登录
function logout() {
    if (socket && isConnected) {
        const username = localStorage.getItem('username');
        const logoutMessage = {
            type: 'system',
            content: `${username}已退出会话`
        };

        socket.send(JSON.stringify(logoutMessage));

        setTimeout(() => {
            socket.close();
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            localStorage.removeItem('user_id');
            window.location.href = '/';
        }, 500);
    } else {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('user_id');
        window.location.href = '/';
    }
}

// 设置事件监听器
sendButton.addEventListener('click', sendMessage);

messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
}

// 搜索用户
async function searchUsers() {
    const query = searchInput.value.trim();
    if (!query) {
        searchResultsContainer.innerHTML = '';
        searchResultsContainer.classList.remove('show');
        return;
    }

    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('搜索失败');
        }

        const users = await response.json();
        renderSearchResults(users);
    } catch (error) {
        console.error('搜索用户失败:', error);
        searchResultsContainer.innerHTML = '<div class="search-error">搜索失败，请重试</div>';
        searchResultsContainer.classList.add('show');
    }
}

// 显示搜索结果
function renderSearchResults(users) {
    searchResultsContainer.innerHTML = '';

    if (users.length === 0) {
        searchResultsContainer.innerHTML = '<div class="no-results">未找到匹配的用户</div>';
        searchResultsContainer.classList.add('show');
        return;
    }

    users.forEach(user => {
        const avatarChar = user.username.charAt(user.username.length - 1);

        const resultItem = document.createElement('div');
        resultItem.classList.add('search-result-item');

        resultItem.innerHTML = `
            <div class="search-result-user">
                <div class="search-result-avatar">${avatarChar}</div>
                <div class="search-result-username">${user.username}</div>
            </div>
            <button class="start-chat-btn" data-user-id="${user.id}">发起会话</button>
        `;

        searchResultsContainer.appendChild(resultItem);
    });

    // 添加点击事件
    const chatButtons = searchResultsContainer.querySelectorAll('.start-chat-btn');
    chatButtons.forEach(button => {
        button.addEventListener('click', () => {
            createSessionWithUser(button.getAttribute('data-user-id'));
        });
    });

    searchResultsContainer.classList.add('show');
}

// 创建与用户的会话
async function createSessionWithUser(userId) {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/sessions/create', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_id: userId })
        });

        if (!response.ok) {
            throw new Error('创建会话失败');
        }

        const sessionData = await response.json();

        // 检查会话是否已在列表中
        const existingSession = sessions.find(s => s.id === sessionData.session_id);
        if (!existingSession) {
            // 创建新会话对象并添加到会话列表
            const newSession = {
                id: sessionData.session_id,
                start_time: sessionData.start_time,
                other_user: sessionData.other_user,
                last_activity: new Date().toISOString()
            };

            sessions.unshift(newSession);
            renderSessionsList();
        }

        // 打开会话
        openSession(sessionData.session_id);

        // 清空搜索结果
        searchResultsContainer.innerHTML = '';
        searchResultsContainer.classList.remove('show');
        searchInput.value = '';
    } catch (error) {
        console.error('创建会话失败:', error);
        alert('创建会话失败，请重试');
    }
}

// 绑定搜索事件
if (searchBtn) {
    searchBtn.addEventListener('click', searchUsers);
}

if (searchInput) {
    searchInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            searchUsers();
        }
    });
}

// 初始化应用
document.addEventListener('DOMContentLoaded', initApp); 