/**
 * WebSocket handler for SecureTalk chat
 */

class ChatSocket {
    constructor(roomSlug) {
        this.roomSlug = roomSlug;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.pingInterval = null;
        this.typingTimeout = null;
        this.lastTypingSent = 0;
        
        // Callbacks
        this.messageHandler = null;
        this.systemMessageHandler = null;
        this.typingHandler = null;
        this.historyHandler = null;
        this.connectionHandler = null;
    }
    
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/chat/${this.roomSlug}/`;
        
        this.socket = new WebSocket(wsUrl);
        
        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;
            this.startPing();
            this.updateConnectionStatus(true);
            
            if (this.connectionHandler) {
                this.connectionHandler(true);
            }
        };
        
        this.socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };
        
        this.socket.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            this.stopPing();
            this.updateConnectionStatus(false);
            
            if (this.connectionHandler) {
                this.connectionHandler(false);
            }
            
            // Attempt reconnection
            if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnect();
            }
        };
        
        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleMessage(data) {
        switch (data.type) {
            case 'message':
                if (this.messageHandler) {
                    this.messageHandler(data);
                }
                break;
            
            case 'system':
                if (this.systemMessageHandler) {
                    this.systemMessageHandler(data.content);
                }
                break;
            
            case 'typing':
                if (this.typingHandler) {
                    this.typingHandler(data);
                }
                break;
            
            case 'history':
                if (this.historyHandler) {
                    this.historyHandler(data.messages);
                }
                break;
            
            case 'pong':
                // Keepalive response received
                break;
            
            default:
                console.log('Unknown message type:', data.type);
        }
    }
    
    send(content) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'message',
                content: content
            }));
        }
    }
    
    sendTyping() {
        const now = Date.now();
        
        // Debounce: only send every second
        if (now - this.lastTypingSent < 1000) {
            return;
        }
        
        this.lastTypingSent = now;
        
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'typing'
            }));
        }
    }
    
    ping() {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'ping'
            }));
        }
    }
    
    startPing() {
        this.pingInterval = setInterval(() => {
            this.ping();
        }, 30000);
    }
    
    stopPing() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }
    
    reconnect() {
        this.reconnectAttempts++;
        console.log(`Reconnecting... Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
        
        setTimeout(() => {
            this.connect();
        }, this.reconnectDelay);
        
        // Exponential backoff
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
    }
    
    disconnect() {
        this.stopPing();
        if (this.socket) {
            this.socket.close(1000, 'User disconnected');
        }
    }
    
    updateConnectionStatus(connected) {
        const statusEl = document.getElementById('connection-status');
        if (statusEl) {
            statusEl.classList.toggle('visible', !connected);
            statusEl.classList.toggle('disconnected', !connected);
            
            const textEl = statusEl.querySelector('.status-text');
            if (textEl) {
                textEl.textContent = connected ? 'Connected' : 'Disconnected';
            }
        }
    }
    
    // Callback setters
    onMessage(handler) {
        this.messageHandler = handler;
    }
    
    onSystemMessage(handler) {
        this.systemMessageHandler = handler;
    }
    
    onTyping(handler) {
        this.typingHandler = handler;
    }
    
    onHistory(handler) {
        this.historyHandler = handler;
    }
    
    onConnection(handler) {
        this.connectionHandler = handler;
    }
}

// Message rendering helpers
function renderMessage(msg, isSelf) {
    const time = new Date(msg.timestamp);
    const timeStr = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    return `
        <div class="message ${isSelf ? 'self' : ''}" data-message-id="${msg.message_id}">
            <div class="message-avatar">
                <img src="/profile/avatar/${msg.author_id}/" alt="${msg.author_username}"
                     onerror="this.src='/static/images/default-avatar.svg'">
            </div>
            <div class="message-content">
                <div class="message-header">
                    <a href="/profile/${msg.author_username}/" class="message-author">${escapeHtml(msg.author_name)}</a>
                    <span class="message-time" title="${time.toLocaleString()}">${timeStr}</span>
                </div>
                <div class="message-text">${escapeHtml(msg.content)}</div>
            </div>
        </div>
    `;
}

function renderSystemMessage(content) {
    return `
        <div class="message system">
            <span class="system-text">${escapeHtml(content)}</span>
        </div>
    `;
}

function renderTypingIndicator(username) {
    return `
        <div class="typing-indicator" data-username="${escapeHtml(username)}">
            <span class="typing-dots">
                <span></span><span></span><span></span>
            </span>
            <span class="typing-text">${escapeHtml(username)} is typing...</span>
        </div>
    `;
}

function removeTypingIndicator(username) {
    const indicator = document.querySelector(`.typing-indicator[data-username="${username}"]`);
    if (indicator) {
        indicator.remove();
    }
}

function scrollToBottom(force = false) {
    const container = document.getElementById('messages-container');
    if (container) {
        if (force) {
            container.scrollTop = container.scrollHeight;
        }
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}