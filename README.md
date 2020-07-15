# shadowsocks_install
静态编译shadowsocks-libev快速部署服务脚本，
通过脚本调用 ss-manager 控制 ss-server
将原本的网页面板操作改为脚本操作。 
支持流量统计、多端口添加删除、端口流量用完强制下线。  
### 使用方法

```Bash
wget --no-check-certificate -O shadowsocks-libev.sh https://github.com/yiguihai/shadowsocks_install/raw/master/Shadowsocks-multi-port.sh
chmod +x shadowsocks-libev.sh
./shadowsocks-libev.sh
```

先 <启动运行> 然后 <添加端口>  
如果已经添加过端口了直接 <启动运行>   
如果担心流量可以选择运行再启动 <监控模式>   
将会对流量用超的端口直接下线。

### 展示图
<img src="https://github.com/yiguihai/shadowsocks_install/raw/master/view.png" alt="展示图" title="查看图片" width="200" height="200" />

### 注意事项
监控模式返回单位为 Bytes
    
脚本不会对防火墙做任何操作，Centos系列系统使用本脚本时：如果Shadwosocks客户端连接不上的可能需要自己关闭防火墙

### 老版本
将会逐渐废弃  
[单端口版](https://github.com/yiguihai/shadowsocks_install/blob/master/README-old.md)
