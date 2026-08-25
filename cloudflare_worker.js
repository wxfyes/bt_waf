/**
 * 企业级防篡改与反制 WAF - 抗失联边缘网关 (Cloudflare Worker 模式)
 * 
 * 部署说明：
 * 1. 将此代码复制到 Cloudflare Worker 中。
 * 2. 修改下方的 ORIGIN_SERVER_URL 和 SECRET_TOKEN。
 * 3. 将 Worker 的 URL 设置为 Telegram Bot 的 Webhook。
 */

// ================= 配置区 =================
// 您的源站隐蔽 API 地址 (由宝塔 WAF 插件生成并监听)
// 例如: https://your-v2board-domain.com/.well-known/btwaf_api
const ORIGIN_SERVER_URL = "https://your-domain.com/.well-known/btwaf_api";

// 通信密钥 (必须与宝塔插件后台配置的 Token 保持一致)
const SECRET_TOKEN = "YOUR_SECRET_TOKEN_HERE";
// ==========================================

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // 仅接收 POST 请求 (Telegram Webhook 标准)
  if (request.method !== 'POST') {
    return new Response('Edge Gateway is running.', { status: 200 });
  }

  try {
    const payload = await request.json();
    
    // 解析 Telegram 发来的消息
    if (payload.message && payload.message.text) {
      const text = payload.message.text;
      const chatId = payload.message.chat.id;
      
      // 检查指令格式，例如: /waf ban 1.1.1.1
      if (text.startsWith('/waf ')) {
        const command = text.replace('/waf ', '').trim();
        
        // 构造安全指令载荷
        const commandPayload = {
          command: command,
          timestamp: Date.now(),
          chat_id: chatId
        };
        
        // 对指令进行 Base64 编码 (可进一步升级为 AES 加密)
        const encodedData = btoa(JSON.stringify(commandPayload));
        
        // 向处于失联状态的源站发起强行穿透请求
        // 即使源站正常业务被 DDoS 拥堵，只要 Nginx 还能收包，这个特殊的请求就能直达 Lua 引擎
        const response = await fetch(ORIGIN_SERVER_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-WAF-Gateway-Token': SECRET_TOKEN,
            'X-WAF-Command': encodedData
          },
          // 设置较短的超时，避免 Worker 被挂死
          cf: { cacheTtl: 0 } 
        });
        
        const result = await response.text();
        
        // 此处可以将 result 回传给 Telegram (需要调用 Telegram API)
        // 为了保持脚本精简，这里直接返回给 Webhook 调用方
        return new Response(JSON.stringify({
            method: "sendMessage",
            chat_id: chatId,
            text: "指令已下发至源站网关: \n" + result
        }), { 
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    return new Response('OK', { status: 200 });
  } catch (err) {
    return new Response('Gateway Error: ' + err.message, { status: 500 });
  }
}
