#!/bin/bash
# 宝塔插件卸载脚本
# 清理全局注入
sed -i '/# BTWAF_GLOBAL_START/,/# BTWAF_GLOBAL_END/d' /www/server/nginx/conf/nginx.conf
# 清理站点注入
sed -i '/# BTWAF_SITE_START/,/# BTWAF_SITE_END/d' /www/server/panel/vhost/nginx/*.conf
# 重载 Nginx
/etc/init.d/nginx reload
# 删除规则文件
rm -rf /www/server/nginx/conf/waf/btwaf_*
rm -rf /www/server/nginx/conf/waf/rules/
