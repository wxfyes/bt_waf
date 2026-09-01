-- 动态注入路径，彻底摆脱 nginx.conf 的 lua_package_path 依赖
if not string.find(package.path, "/www/server/nginx/conf/waf") then
    package.path = "/www/server/nginx/conf/waf/?.lua;" .. package.path
end

local config = require("btwaf_init")

if config.waf_enable ~= "on" then
    return
end

-- 极简绝对探针：只要请求进入，无条件记录！
local probe_file = io.open(config.log_dir .. "probe.log", "a")
if probe_file then
    probe_file:write(string.format("[%s] PROBE HIT! URI: %s\n", ngx.localtime(), ngx.var.request_uri))
    probe_file:close()
end



-- 引入依赖库
local tarpit = require("btwaf_tarpit")

local req_uri = ngx.var.request_uri
local req_method = ngx.req.get_method()

-- 获取真实客户端 IP (兼容开启小云朵 Cloudflare 或 CDN 代理的情况)
local function get_client_ip()
    local headers = ngx.req.get_headers()
    -- 必须优先取 X-Forwarded-For，因为如果是 CF Worker 反代，CF-Connecting-IP 会变成 Worker 节点的 IP
    local ip = headers["X-Forwarded-For"] 
            or headers["CF-Connecting-IP"] 
            or headers["X-Real-IP"] 
            or ngx.var.remote_addr
    
    -- 如果是列表，取逗号前的第一个真实 IP（兼容 IPv4 和 IPv6）
    if ip and string.find(ip, ",") then
        local first_ip = string.match(ip, "^%s*([^,]+)")
        if first_ip then ip = first_ip end
    end
    return ip
end

local client_ip = get_client_ip()

-- 记录拦截日志 (自动按日切割)
local function log_record(rule, payload, action)
    local date_str = ngx.today() -- 格式: YYYY-MM-DD
    local ua = ngx.var.http_user_agent or "null"
    local log_str = string.format("[%s] IP: %s, URI: %s, UA: %s, Rule: %s, Payload: %s, Action: %s\n", 
                                  ngx.localtime(), client_ip, req_uri, ua, rule, payload, action)
    
    -- 写入 Nginx 错误日志作为备份
    ngx.log(ngx.ERR, "[WAF-Intercept] ", log_str)
    
    -- 智能写入到独立的每日日志文件
    local log_file = string.format("%sintercept_%s.log", config.log_dir, date_str)
    local file, err = io.open(log_file, "a")
    if file then
        file:write(log_str)
        file:close()
    else
        ngx.log(ngx.ERR, "Failed to open WAF log file: ", err)
    end
end

-- 注入调试标记
ngx.header["X-WAF-Status"] = "running"
ngx.header["X-WAF-Rules"] = tostring(type(_G.waf_rules))

-- Tarpit 惩罚
local function trigger_penalty(rule, payload)
    log_record(rule, payload, config.drop_action)
    
    -- 【防自杀保护】如果是自我测试探针，绝对不要进入 Tarpit，否则会耗尽用户浏览器的连接池导致网站假死！
    local action = config.drop_action
    if rule == "WAF Self-Test" then
        action = "block"
    end

    if action == "tarpit" then
        tarpit.execute()
    elseif action == "block" then
        ngx.status = 406
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say(string.format([[
        <html><head><title>WAF 拦截</title><style>body{background:#1e1e1e;color:#ff3333;font-family:monospace;padding:50px;text-align:center;}h1{font-size:40px;}</style></head>
        <body><h1>🛑 恶意请求已被 WAF 处决 🛑</h1><p>触发规则: %s</p><p>攻击特征: %s</p></body></html>
        ]], rule, payload))
        ngx.exit(406)
    else
        ngx.exit(444) -- 直接断开连接 (drop)
    end
end

-- 正则匹配引擎 (移除 JIT j 标记，兼容所有环境)
local function match_rules(data, ruleset_name)
    if not data or not _G.waf_rules[ruleset_name] then return false end
    
    local rules = _G.waf_rules[ruleset_name]
    for _, rule in ipairs(rules) do
        if type(data) == "table" then
            for key, val in pairs(data) do
                if type(val) == "string" and ngx.re.find(val, rule, "io") then
                    return rule, val
                end
            end
        elseif type(data) == "string" then
            if ngx.re.find(data, rule, "io") then
                return rule, data
            end
        end
    end
    return false
end

-- ================= 主防御逻辑 ================= --

-- 【静态资源放行】直接放行图片、样式、脚本等，避免浪费 CPU 及误触 CC 频率限制
if ngx.re.match(ngx.var.uri, "\\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|mp4|avi|mp3|zip|rar|gz|7z)$", "io") then
    return
end

-- 【终极自检后门】如果 URL 包含 test_waf=1，无条件直接处决！
if string.find(ngx.var.request_uri, "test_waf=1") then
    trigger_penalty("WAF Self-Test", "test_waf=1")
    return
end

local site_framework = ngx.var.btwaf_framework or config.framework or "general"
local req_uri = ngx.var.request_uri



-- 0. IP 黑名单检测
if _G.waf_rules.blacklist then
    local rules = _G.waf_rules.blacklist
    for _, rule in ipairs(rules) do
        if client_ip == rule then
            trigger_penalty("IP Blacklist", rule)
            return
        end
    end
end

-- ================= 全局服务通信白名单 ================= --
-- V2Board/Xboard/各种探针 专属放行逻辑（API 订阅与服务端节点通信免死金牌）
-- 必须在扫描器 UA 和空 UA 检测之前，因为 Telegram Webhook 没有 UA，节点和订阅也常被误杀
if string.find(req_uri, "/api/v1/client/") or string.find(req_uri, "/api/v1/server/") or string.find(req_uri, "/api/clients/") or string.find(req_uri, "/api/v1/guest/") or string.find(req_uri, "/ktelie/") or string.find(req_uri, "webhook") then
    return
end

-- 0.5 空 User-Agent 斩杀 (绝杀极简探测器与 GFW 主动嗅探)
local ua = ngx.var.http_user_agent
if not ua or ua == "" then
    trigger_penalty("Empty User-Agent", "null")
    return
end

-- 0.6 恶意扫描器 User-Agent 检测
local match, payload = match_rules(ua, "user_agent")
if match then
    trigger_penalty("Malicious User-Agent/Scanner", payload)
    return
end

-- 0.8 CC 攻击频率检测
if config.cc_enable == "on" then
    local cc_dict = ngx.shared.btwaf_ip_scores
    if cc_dict then
        local req_count, err = cc_dict:get(client_ip)
        if req_count then
            -- 动态阈值：如果是 V2Board 的用户业务路径（除了敏感的登录注册），阈值自动放宽 3 倍，完美兼容客户端高频并发
            local limit = tonumber(config.cc_rate) or 30
            if site_framework == "v2board" and string.find(req_uri, "/api/v1/user/") then
                limit = limit * 3
            end
            
            if req_count > limit then
                trigger_penalty("CC Attack", "High Frequency")
                return
            else
                cc_dict:incr(client_ip, 1)
            end
        else
            cc_dict:set(client_ip, 1, 10) -- 10秒一个统计周期
        end
    end
end

-- 0.9 GeoIP 检测 (兼容 Cloudflare 与 Nginx GeoIP)
if config.geoip_enable == "on" then
    local headers = ngx.req.get_headers()
    local country = headers["CF-IPCountry"] or ngx.var.geoip_country_code or ngx.var.geoip2_data_country_code
    if country and country ~= "" and country ~= "XX" then
        local allowed = false
        if config.geoip_regions then
            for allowed_country in string.gmatch(config.geoip_regions, "[A-Z0-9]+") do
                if country == allowed_country then
                    allowed = true
                    break
                end
            end
        end
        if not allowed then
            trigger_penalty("GeoIP Block", country)
            return
        end
    end
end

-- 1. 框架专属防御
if site_framework == "v2board" then
    local match, payload = match_rules(req_uri, "v2board")
    if match then
        trigger_penalty("V2Board Specific Protection", payload)
        return
    end
end

-- 1.6 Cookie 注入检测
local cookie = ngx.var.http_cookie
if cookie then
    local match, payload = match_rules(cookie, "cookie")
    if match then
        trigger_penalty("Cookie Injection", payload)
        return
    end
end

-- 2. GET 参数注入检测
if req_method == "GET" then
    local args = ngx.req.get_uri_args()
    local match, payload = match_rules(args, "args")
    if match then
        trigger_penalty("GET Injection", payload)
        return
    end
end

-- 3. POST 数据检测 (SQLi/XSS/恶意上传)
if req_method == "POST" and config.check_post == "on" then
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    if args then
        local match, payload = match_rules(args, "post")
        if match then
            trigger_penalty("POST Injection", payload)
            return
        end
    end
    
    -- 文件上传恶意代码深度检测 (防图片马)
    -- 注意: 完整实现需解析 multipart/form-data，检测扩展名及文件头和尾
    -- 这里简化展示逻辑架构
end

-- 如果全放行，进入源站
