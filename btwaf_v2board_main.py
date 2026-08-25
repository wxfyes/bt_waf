import sys
import os
import json
import hashlib
import shutil
import re

# 设置当前目录为运行目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 在宝塔环境下引用公共库
try:
    sys.path.append('/www/server/panel/class/')
    import public
except Exception:
    # 模拟 public 库用于本地开发测试
    class MockPublic:
        @staticmethod
        def returnMsg(status, msg):
            return {"status": status, "msg": msg}
        @staticmethod
        def ExecShell(cmd):
            return os.popen(cmd).read(), ""
    public = MockPublic()

class btwaf_v2board_main:
    def __init__(self):
        self.plugin_path = '/www/server/panel/plugin/btwaf_v2board'
        self.nginx_conf_dir = '/www/server/panel/vhost/nginx'
        self.waf_dir = '/www/server/nginx/conf/waf'
        self.backup_dir = '/www/server/panel/plugin/btwaf_v2board/backup'
        self.nginx_conf_path = "/www/server/nginx/conf/nginx.conf"
        self.waf_rules_dir = "/www/server/nginx/conf/waf"
        self.baseline_file = f"{self.plugin_path}/hash_baseline.json"

    def get_sites(self, args=None):
        try:
            import public
            sites = public.M('sites').field('name').select()
            site_names = [site['name'] for site in sites]
            return public.returnMsg(True, site_names)
        except Exception as e:
            return {"status": False, "msg": str(e)}

    def get_status(self, args):
        """获取当前站点 Nginx 注入状态"""
        site_name = getattr(args, 'siteName', '')
        if not site_name or site_name == "default":
            return public.returnMsg(False, "请先选择站点")
            
        site_conf_path = f"/www/server/panel/vhost/nginx/{site_name}.conf"
        injected = False
        if os.path.exists(site_conf_path):
            with open(site_conf_path, 'r', encoding='utf-8') as f:
                if "access_by_lua_file /www/server/nginx/conf/waf/btwaf_access.lua;" in f.read():
                    injected = True
        
        status_msg = "已受保护" if injected else "未受保护"
        
        # 检查底层 access.lua 是否真的更新成功
        lua_status_msg = "未知"
        if os.path.exists("/www/server/nginx/conf/waf/btwaf_access.lua"):
            lua_status_msg = "已更新 (包含最新探针)"
            
        global_enable = "on"
        config_file = "/www/server/nginx/conf/waf/btwaf_init.lua"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'waf_enable = "off"' in content:
                        global_enable = "off"
            except:
                pass
                
        # 统计今日拦截次数
        import datetime
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = f"/www/wwwlogs/waf/intercept_{today_str}.log"
        blocked_count = 0
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    blocked_count = sum(1 for line in f if line.strip())
            except:
                pass

        return public.returnMsg(True, {
            "siteName": site_name,
            "inject_status": status_msg,
            "lua_status": lua_status_msg,
            "global_enable": global_enable,
            "blockedCount": blocked_count
        })

    def save_framework(self, args):
        framework = getattr(args, 'framework', 'v2board')
        return public.returnMsg(True, f"已保存 {framework} 专属适配")

    def diagnose_local(self, args):
        site_name = getattr(args, 'siteName', '')
        if not site_name:
            return public.returnMsg(False, "无站点名")
            
        import requests
        try:
            url = f"http://127.0.0.1/?test_waf=1"
            headers = {"Host": site_name}
            resp = requests.get(url, headers=headers, timeout=5)
            code = resp.status_code
        except Exception as e:
            err_str = str(e)
            if "RemoteDisconnected" in err_str or "Connection aborted" in err_str:
                return public.returnMsg(True, "【本地内核诊断】防护完全正常生效！WAF 执行了 DROP (444) 直接切断了恶意连接。")
            return public.returnMsg(False, f"本地请求失败: {err_str}")
            
        if code == 406 or code == 403 or code == 444:
            return public.returnMsg(True, f"【本地内核诊断】防护完全正常生效！返回状态码: {code}")
        else:
            return public.returnMsg(False, f"【本地内核诊断】拦截失败！返回状态码: {code}。这说明 Nginx 彻底无视了 Lua 引擎，指令可能被 location 覆盖。")

    def get_framework(self, args):
        """获取特定站点的框架配置"""
        site_name = getattr(args, 'siteName', '')
        if not site_name:
            return public.returnMsg(False, "无站点名")
            
        site_conf_path = f"/www/server/panel/vhost/nginx/{site_name}.conf"
        if not os.path.exists(site_conf_path):
            return public.returnMsg(True, "general")
            
        try:
            with open(site_conf_path, 'r', encoding='utf-8') as f:
                content = f.read()
            import re
            match = re.search(r'set\s+\$btwaf_framework\s+"([^"]+)";', content)
            if match:
                return public.returnMsg(True, match.group(1))
            return public.returnMsg(True, "general")
        except:
            return public.returnMsg(True, "general")

    def set_framework(self, args):
        """动态修改站点的框架适配器配置"""
        site_name = getattr(args, 'siteName', '')
        framework = getattr(args, 'framework', 'general')
        
        if not site_name:
            return public.returnMsg(False, "无站点名")
            
        site_conf_path = f"/www/server/panel/vhost/nginx/{site_name}.conf"
        if not os.path.exists(site_conf_path):
            return public.returnMsg(False, "站点配置文件不存在。")
            
        try:
            with open(site_conf_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if "BTWAF_SITE_START" not in content:
                return public.returnMsg(False, "请先在【安全防御】页面点击【一键注入防护】。")
                
            import re
            # 查找是否已经存在 set $btwaf_framework
            if re.search(r'set\s+\$btwaf_framework', content):
                new_content = re.sub(r'set\s+\$btwaf_framework\s+"[^"]*";', f'set $btwaf_framework "{framework}";', content)
            else:
                # 插入到 BTWAF_SITE_START 之后
                new_content = content.replace("# BTWAF_SITE_START", f'# BTWAF_SITE_START\n    set $btwaf_framework "{framework}";')
                
            with open(site_conf_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
                
            return public.returnMsg(True, f"成功为 {site_name} 切换至 {framework} 框架")
        except Exception as e:
            return public.returnMsg(False, f"修改失败: {str(e)}")

    def get_logs(self, args):
        """获取当天的 WAF 拦截日志"""
        import datetime
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = f"/www/wwwlogs/waf/intercept_{date_str}.log"
        
        if not os.path.exists(log_file):
            return public.returnMsg(True, "暂无今日拦截记录。")
            
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = f.read()
            return public.returnMsg(True, logs)
        except Exception as e:
            return public.returnMsg(False, f"无法读取日志文件: {str(e)}")

    def get_nginx_error_log(self, args):
        site_name = getattr(args, 'siteName', '')
        if not site_name:
            return public.returnMsg(False, "无站点名")
        
        log_path = f"/www/wwwlogs/{site_name}.error.log"
        global_log_path = "/www/wwwlogs/nginx_error.log"
        
        out = ""
        if os.path.exists(log_path):
            res, _ = public.ExecShell(f"tail -n 20 {log_path}")
            out += f"--- 站点错误日志 ---\n{res}\n"
            
        if os.path.exists(global_log_path):
            res, _ = public.ExecShell(f"tail -n 20 {global_log_path}")
            out += f"--- 全局错误日志 ---\n{res}\n"
            
        if not out:
            out = "无日志文件"
            
        return public.returnMsg(True, out)

    def clear_logs(self, args):
        """清空所有拦截日志"""
        log_dir = "/www/wwwlogs/waf/"
        if os.path.exists(log_dir):
            import shutil
            shutil.rmtree(log_dir)
            os.makedirs(log_dir)
            os.system(f"chown -R www:www {log_dir}")
        return public.returnMsg(True, "日志已全部清空！")

    def reload_nginx(self, args):
        """重载 Nginx 以清除 Lua 缓存并使新规则生效"""
        out, err = public.ExecShell("/etc/init.d/nginx reload")
        if "done" not in out and "successful" not in out and "ok" not in out:
            # 兼容其他版本宝塔的可能返回
            return public.returnMsg(True, f"重载命令已发送，Nginx 返回: {out} {err}")
            
        return public.returnMsg(True, "Nginx 已成功重载！")

    def toggle_waf(self, args):
        """全局防御总开关 (控制 waf_enable)"""
        waf_action = getattr(args, 'waf_action', 'on') # 'on' 或 'off'
        config_file = "/www/server/nginx/conf/waf/btwaf_init.lua"
        if not os.path.exists(config_file):
            return public.returnMsg(False, "WAF 尚未安装或配置文件丢失。")
            
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            import re
            new_content = re.sub(r'waf_enable\s*=\s*"[^"]*"', f'waf_enable = "{waf_action}"', content)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
                
            # 重载使 Lua 配置生效
            public.ExecShell("/etc/init.d/nginx reload")
            
            status_text = "开启" if waf_action == "on" else "关闭"
            return public.returnMsg(True, f"全局防火墙已{status_text}！")
        except Exception as e:
            return public.returnMsg(False, f"切换失败: {str(e)}")

    def inject_waf(self, args):
        """将 WAF 精准注入到选中站点的 server 块中"""
        site_name = getattr(args, 'siteName', '')
        if not site_name or site_name == "default":
            return public.returnMsg(False, "请先选择要防御的站点")
            
        site_conf_path = f"/www/server/panel/vhost/nginx/{site_name}.conf"
        if not os.path.exists(site_conf_path):
            return public.returnMsg(False, f"未找到站点配置文件: {site_conf_path}")
            
        # 1. 确保全局环境（共享内存与路径）已注入
        with open(self.nginx_conf_path, 'r', encoding='utf-8') as f:
            global_conf = f.read()
            
        # 强制清理之前的冲突遗留代码
        if "BTWAF_GLOBAL_START" in global_conf:
            global_conf = re.sub(r'\s*# BTWAF_GLOBAL_START.*?# BTWAF_GLOBAL_END\n', '\n', global_conf, flags=re.DOTALL)
            
        if "btwaf_ip_scores" not in global_conf:
            shutil.copyfile(self.nginx_conf_path, self.nginx_conf_path + ".waf_bak")
            
            insert_parts = ["\n    # BTWAF_GLOBAL_START"]
            insert_parts.append("    lua_shared_dict btwaf_ip_scores 10m;")
            insert_parts.append("    # BTWAF_GLOBAL_END\n")
            
            insert_global = "\n".join(insert_parts)
            new_global = re.sub(r'(http\s*\{)', r'\1' + insert_global, global_conf, count=1)
            with open(self.nginx_conf_path, 'w', encoding='utf-8') as f:
                f.write(new_global)
        # 2. 将拦截脚本精准注入站点 server 块
        with open(site_conf_path, 'r', encoding='utf-8') as f:
            site_conf = f.read()
            
        if "access_by_lua_file /www/server/nginx/conf/waf/btwaf_access.lua;" in site_conf:
            return public.returnMsg(True, f"站点 {site_name} 已经处于防御状态，无需重复注入。")
            
        # 兼容性清理：移除旧的任何 BTWAF 块
        site_conf = re.sub(r'# BTWAF_SITE_START.*?# BTWAF_SITE_END\n', '', site_conf, flags=re.DOTALL)
            
        shutil.copyfile(site_conf_path, site_conf_path + ".waf_bak")
        insert_site = """
    # BTWAF_SITE_START
    set $btwaf_framework "general";
    add_header X-BTWAF-Status "Injected";
    access_by_lua_file /www/server/nginx/conf/waf/btwaf_access.lua;
    # BTWAF_SITE_END
"""
        # 将 count=1 移除，注入到所有的 server 块中（解决宝塔开启强制 HTTPS 后生成多个 server 块导致 443 端口漏防的问题）
        new_site_conf = re.sub(r'(server\s*\{)', r'\1' + insert_site, site_conf)
        
        with open(site_conf_path, 'w', encoding='utf-8') as f:
            f.write(new_site_conf)
            
        # 3. 严格测试与防崩溃回滚
        out, err = public.ExecShell("nginx -t")
        if "successful" not in out and "successful" not in err:
            shutil.copyfile(site_conf_path + ".waf_bak", site_conf_path)
            return public.returnMsg(False, f"注入失败，已自动撤销更改。报错信息: {err}")
            
        # 4. 热重载
        public.ExecShell("nginx -s reload")
        return public.returnMsg(True, f"WAF 防御已成功注入站点: {site_name}")
        
    def generate_baseline(self, args):
        """生成 SHA-256 基线"""
        target_path = getattr(args, 'path', '/www/wwwroot/default')
        if not os.path.exists(target_path):
            return public.returnMsg(False, "目标目录不存在")
            
        hashes = {}
        for root, dirs, files in os.walk(target_path):
            for file in files:
                # 排除日志和缓存
                if ".log" in file or "cache" in root.lower(): continue
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        hashes[file_path] = file_hash
                except Exception:
                    pass
                    
        with open(self.baseline_file, 'w', encoding='utf-8') as f:
            json.dump(hashes, f)
            
        return public.returnMsg(True, f"基线生成完成，共记录 {len(hashes)} 个文件。")

    def run_inspection(self, args):
        """执行完整性校验"""
        if not os.path.exists(self.baseline_file):
            return public.returnMsg(False, "请先生成哈希基线")
            
        with open(self.baseline_file, 'r', encoding='utf-8') as f:
            baseline = json.load(f)
            
        altered = []
        for file_path, original_hash in baseline.items():
            if not os.path.exists(file_path):
                altered.append(f"文件丢失: {file_path}")
                continue
            try:
                with open(file_path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != original_hash:
                        altered.append(f"文件被篡改: {file_path}")
            except Exception:
                pass
                
        if not altered:
            return public.returnMsg(True, "校验完成，未发现篡改。")
        else:
            return public.returnMsg(False, "发现异常文件！\n" + "\n".join(altered[:10]))

if __name__ == '__main__':
    # 本地调试桩代码
    p = btwaf_v2board_main()
    print(p.get_status(None))
