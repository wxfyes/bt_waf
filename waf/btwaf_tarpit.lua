local _M = {}

function _M.execute()
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.status = 200
    ngx.send_headers()
    
    -- Tarpit 循环：以极慢的速度发送无尽的垃圾数据，消耗攻击者的连接资源
    -- 模拟 "资源耗尽型反制"
    local chunk = "<!-- " .. string.rep(" ", 1024) -- 1KB 空白数据块
    ngx.print("<html><body>")
    -- local dict = ngx.shared.btwaf_ip_scores
    -- local score, err = dict:get(ip)
    for i = 1, 300 do -- 持续数分钟
        local ok, err = ngx.print(chunk)
        if not ok then
            -- 如果客户端已经主动断开，退出陷阱
            break
        end
        ngx.flush(true)
        -- 睡眠 1 秒
        ngx.sleep(1)
    end
    
    ngx.exit(406)
end

return _M
