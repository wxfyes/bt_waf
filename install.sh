#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
install_tmp='/tmp/bt_install.pl'

pluginPath=/www/server/panel/plugin/btwaf_v2board
nginxWafPath=/www/server/nginx/conf/waf

Install_btwaf_v2board()
{
    echo '正在安装 企业级防篡改与反制WAF...'
    
    # 创建必要的目录
        # Create Nginx WAF directories
        mkdir -p $nginxWafPath/rules
        mkdir -p /www/wwwlogs/waf/

        # 解除可能存在的不可变锁定，确保文件能被最新版覆盖！
        chattr -i -R $nginxWafPath 2>/dev/null
        chattr -i -R $pluginPath 2>/dev/null
        
        # In aaPanel, the zip is often directly extracted to the target plugin path.
        if [ -d "./waf" ]; then
            \cp -rf ./waf/* $nginxWafPath/
        elif [ -d "$pluginPath/waf" ]; then
            \cp -rf $pluginPath/waf/* $nginxWafPath/
        fi
        
        # 确保 rules 目录权限和独立性
        chmod -R 755 $nginxWafPath/rules
        
        # Copy Icon to aaPanel static folder
        mkdir -p /www/server/panel/BTPanel/static/img/soft_ico/
        if [ -f "./icon.png" ]; then
            \cp -f ./icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-btwaf_v2board.png
        elif [ -f "$pluginPath/icon.png" ]; then
            \cp -f $pluginPath/icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-btwaf_v2board.png
        fi
        
        # Set permissions
        chown -R www:www $nginxWafPath
        chown -R www:www /www/wwwlogs/waf/

        echo '1' > $install_tmp
}

Uninstall_btwaf_v2board()
{
    echo '正在卸载...'
    
    # 移除注入的配置 (需在 python 侧实现，这里做简单的清理)
    rm -rf $pluginPath
    rm -rf $nginxWafPath
    
    echo '卸载成功' > $install_tmp
}

action=$1
if [ "${1}" == 'install' ];then
    Install_btwaf_v2board
elif [ "${1}" == 'uninstall' ];then
    Uninstall_btwaf_v2board
fi
