// 简单的内存限流存储（生产环境建议使用 Redis）
// 注意：Vercel Serverless 函数是无状态的，这个方案适合低流量场景
// 高流量场景建议使用 Redis 或 Upstash

// 使用全局 Map（在同一个实例中共享，但 Vercel 会冷启动，多个实例间不共享）
// 这是一个简化方案，适合中小流量
const rateLimitStore = new Map();

// 清理过期记录的间隔（分钟）
const CLEANUP_INTERVAL = 5;

// 定期清理过期记录
if (typeof setInterval !== 'undefined') {
    setInterval(() => {
        const now = Date.now();
        for (const [key, data] of rateLimitStore.entries()) {
            if (data.resetTime < now) {
                rateLimitStore.delete(key);
            }
        }
    }, CLEANUP_INTERVAL * 60 * 1000);
}

function getClientIdentifier(req) {
    // 获取客户端标识：优先使用 X-Forwarded-For（Vercel 代理头），否则使用 IP
    const forwardedFor = req.headers['x-forwarded-for'];
    const ip = forwardedFor ? forwardedFor.split(',')[0] : req.socket.remoteAddress;
    // 加上 User-Agent 的一部分作为辅助标识（防止同一 IP 多设备）
    const userAgent = req.headers['user-agent'] || '';
    const deviceType = userAgent.includes('Mobile') ? 'mobile' : 'desktop';
    return `${ip}:${deviceType}`;
}

function checkRateLimit(identifier) {
    const now = Date.now();
    const record = rateLimitStore.get(identifier);
    
    // 配置限流参数
    const MAX_ATTEMPTS = 5;      // 最大尝试次数
    const WINDOW_MS = 15 * 60 * 1000;  // 时间窗口：15分钟
    const LOCKOUT_MS = 60 * 60 * 1000; // 锁定时间：1小时（超过最大次数后）
    
    if (!record) {
        // 首次尝试
        rateLimitStore.set(identifier, {
            attempts: 1,
            firstAttempt: now,
            resetTime: now + WINDOW_MS,
            lockedUntil: null
        });
        return { allowed: true };
    }
    
    // 检查是否在锁定中
    if (record.lockedUntil && record.lockedUntil > now) {
        const remainingLockout = Math.ceil((record.lockedUntil - now) / 1000 / 60);
        return { 
            allowed: false, 
            reason: `尝试次数过多，请 ${remainingLockout} 分钟后重试`,
            remainingLockout
        };
    }
    
    // 重置锁定（锁定时间已过）
    if (record.lockedUntil && record.lockedUntil <= now) {
        record.lockedUntil = null;
        record.attempts = 0;
    }
    
    // 重置窗口（时间窗口已过）
    if (record.resetTime < now) {
        record.attempts = 0;
        record.resetTime = now + WINDOW_MS;
    }
    
    // 检查是否超过最大尝试次数
    if (record.attempts >= MAX_ATTEMPTS) {
        record.lockedUntil = now + LOCKOUT_MS;
        const remainingLockout = Math.ceil(LOCKOUT_MS / 1000 / 60);
        return { 
            allowed: false, 
            reason: `尝试次数过多，已锁定 ${remainingLockout} 分钟`,
            remainingLockout
        };
    }
    
    // 增加尝试次数
    record.attempts++;
    return { 
        allowed: true,
        remainingAttempts: MAX_ATTEMPTS - record.attempts
    };
}

export default async function handler(req, res) {
    // 设置安全头
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    
    // 添加安全响应头
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    
    // 处理预检请求
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }
    
    // 只接受 POST 请求
    if (req.method !== "POST") {
        return res.status(405).json({ success: false, message: "方法不允许" });
    }
    
    try {
        const { password } = req.body;
        
        // 基础验证：密码不能为空
        if (!password || typeof password !== 'string') {
            return res.status(400).json({ success: false, message: "请输入密码" });
        }
        
        // 密码长度限制（防止过长输入的攻击）
        if (password.length > 100) {
            return res.status(400).json({ success: false, message: "密码长度无效" });
        }
        
        // 获取客户端标识并进行限流检查
        const clientId = getClientIdentifier(req);
        const rateLimit = checkRateLimit(clientId);
        
        if (!rateLimit.allowed) {
            return res.status(429).json({ 
                success: false, 
                message: rateLimit.reason,
                remainingLockout: rateLimit.remainingLockout
            });
        }
        
        // 从环境变量获取正确的密码（支持多个密码，用逗号分隔）
        const correctPasswordEnv = process.env.AUTH_PASSWORD || "";
        const validPasswords = correctPasswordEnv.split(',').map(p => p.trim()).filter(p => p);
        
        if (validPasswords.length === 0) {
            console.error("AUTH_PASSWORD 环境变量未设置");
            return res.status(500).json({ success: false, message: "服务器配置错误，请联系管理员" });
        }
        
        // 验证密码（使用恒定时间比较，防止时序攻击）
        const isValid = validPasswords.some(validPassword => {
            if (password.length !== validPassword.length) return false;
            let result = 0;
            for (let i = 0; i < password.length; i++) {
                result |= password.charCodeAt(i) ^ validPassword.charCodeAt(i);
            }
            return result === 0;
        });
        
        // 记录验证结果到控制台（用于审计）
        const now = new Date().toISOString();
        console.log(`[${now}] 验证尝试 - IP: ${clientId.split(':')[0]}, 结果: ${isValid ? '成功' : '失败'}, 剩余次数: ${rateLimit.remainingAttempts || 'N/A'}`);
        
        if (isValid) {
            // 验证成功，清除该客户端的限流记录（可选）
            rateLimitStore.delete(clientId);
            
            // 生成会话 token（可选，增加安全性）
            const crypto = await import('crypto');
            const sessionToken = crypto.randomBytes(32).toString('hex');
            
            return res.status(200).json({ 
                success: true,
                sessionToken: sessionToken  // 返回 token 用于后续验证
            });
        } else {
            return res.status(401).json({ 
                success: false, 
                message: `密码错误，还剩 ${rateLimit.remainingAttempts || 0} 次尝试机会`,
                remainingAttempts: rateLimit.remainingAttempts || 0
            });
        }
    } catch (error) {
        console.error("验证错误:", error);
        return res.status(500).json({ success: false, message: "服务器内部错误，请稍后重试" });
    }
}
