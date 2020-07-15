# shadowsocks_install
静态编译shadowsocks快速部署服务，脚本、编译文件更新随缘。
懒蛇🐍一条…

已全部静态编译。文件x86_64平台64位可用


### 使用方法

使用root用户登录，运行以下命令：

```

wget --no-check-certificate -O shadowsocks-libev.sh https://raw.githubusercontent.com/yiguihai/shadowsocks_install/master/shadowsocks-libev.sh
chmod +x shadowsocks-libev.sh
./shadowsocks-libev.sh 2>&1 | tee shadowsocks-libev.log

```

### 卸载方法

```

./shadowsocks-libev.sh uninstall  

```
### 启动脚本

启动脚本后面的参数含义，从左至右依次为：启动，停止，重启，查看状态。
```
/etc/init.d/shadowsocks-libev start | stop | restart | status
```
### 默认配置文件
```
/etc/shadowsocks-libev/config.json
```
