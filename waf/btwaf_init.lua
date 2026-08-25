local config = {
    -- 核心配置
    waf_enable = "on",           -- WAF 开关
    log_dir = "/www/wwwlogs/waf/", -- 日志目录
    rule_dir = "/www/server/nginx/conf/waf/rules/", -- 规则目录
    
    -- 风控策略 (智能评分机制)
    risk_score_limit = 100,      -- 累积多少分触发封禁
    drop_action = "block",      -- 封禁动作: drop (直接断开), tarpit (资源消耗陷阱), block (返回红色警告页)
    
    -- 框架适配器
    framework = "v2board",       -- 当前适配的框架 (可由 Python 后端动态修改配置)
    
    -- 高级防御机制
    check_post = "on",           -- 检查 POST 数据
    check_cookie = "on",         -- 检查 Cookie
    check_upload = "on",         -- 检查文件上传 (防图片马)
    
    -- 缓存机制 (用于记录 IP 评分)
    -- 注意: 需要在 nginx http 段配置 lua_shared_dict waf_ip_scores 10m;
}

-- 加载规则库的通用函数
local function load_rules(rule_file)
    local path = config.rule_dir .. rule_file
    local file = io.open(path, "r")
    if file == nil then
        return {}
    end
    
    local content = file:read("*a")
    file:close()
    
    -- 简单按行分割作为正则规则 (实际开发可引入 cjson 解析更复杂的格式)
    local rules = {}
    for line in string.gmatch(content, "[^\r\n]+") do
        if line ~= "" and not string.match(line, "^#") then
            table.insert(rules, line)
        end
    end
    return rules
end

-- 全局加载规则到内存，提高性能
_G.waf_rules = {
    args = load_rules("args.rule"),
    post = load_rules("post.rule"),
    cookie = load_rules("cookie.rule"),
    user_agent = load_rules("user_agent.rule"),
    v2board = load_rules("v2board.rule") -- 专属适配规则
}
_G.waf_config = config

return config
