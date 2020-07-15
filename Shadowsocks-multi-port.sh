#!/usr/bin/env bash
#export PATH=$PATH:$PWD
#set -e # 出错退出 太过严格仅限调试使用
#遇上了shell管道循环陷阱，无法获取循环内的自增变量
NOW_PID=$$
DIR="/usr/local/bin"
URL="https://github.com/yiguihai/shadowsocks_install/raw/master/"
HOME="$(pwd)/SS-MANAGER"
OBFS_HOST="checkappexec.microsoft.com"
CONF_FILE=$HOME/shadowsocks-manager.conf
PORT_FILE=$HOME/port.list
ACL_FILE=$HOME/server_block.acl

# Stream Ciphers
common_ciphers=(
rc4-md5
aes-128-cfb
aes-192-cfb
aes-256-cfb
aes-128-ctr
aes-192-ctr
aes-256-ctr
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
salsa20
chacha20
chacha20-ietf
aes-128-gcm
aes-192-gcm
aes-256-gcm
chacha20-ietf-poly1305
xchacha20-ietf-poly1305
)
url_list_ipv4=(
ipv4.icanhazip.com
ipinfo.io/ip
ifconfig.me
api.ipify.org
)
#myip.ipip.net

# libev obfuscating
obfs_libev=(http tls)

Rand()(
  min=$1
  max=$(($2-$min+1))
  num=$(($RANDOM+1000000000)) #增加一个10位的数再求余
  echo $(($num%$max+$min))
)

color_array=(
$(Rand 1 7)
$(Rand 31 36)
$(Rand 41 47)
$(Rand 91 97)
$(Rand 101 107)
)

Author(){
  color=${color_array[$(Rand 1 5)]}
  echo -e "=========== \033[1mShadowsocks-libev\033[0m 多端口管理脚本 by \033[${color}m爱翻墙的红杏\033[0m ==========="
}

Download(){
  wget --no-check-certificate -q -c -t2 -T8 -O $1 $2
  if [ $? -ne 0 ]; then
    echo -e "\033[31m错误: \033[0m下载 $1 文件时失败！"
    rm -f $1
    Exit
  fi
}

Urlencodepipe(){
  local LANG=C; local c; while IFS= read -r c; do
    case $c in [a-zA-Z0-9.~_-]) printf "$c"; continue ;; esac
    printf "$c" | od -An -tx1 | tr ' ' % | tr -d '\n'
  done <<EOF
$(fold -w1)
EOF
  echo
}

Urlencode()(
  printf "$*"|Urlencodepipe;
)

Address(){
  echo "正在检测网络信息..."
  unset -v ipv4 ipv6 addr
  ipv4=$(ip addr|egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'|egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\."|head -n 1)
  ipv6=$(wget -qO- -t1 -T3 ipv6.icanhazip.com)
  #addr=$(wget -qO- -t2 -T4 -U 'curl/7.65.0' cip.cc|grep '地址'|cut -d':' -f2|sed 's/^[ \t]*//g')
  addr=$(wget -qO- -t2 -T4 -U 'curl/7.65.0' myip.ipip.net)
  addr=${addr##*\来\自\于}
  addr=${addr:1}
  if [ -z "$ipv4" ]; then
    for i in ${url_list_ipv4[@]}; do
      ipv4=$(wget -qO- -t1 -T2 $i)
      [ -n "$ipv4" ]&&continue
    done
  fi
  if [ -z "$addr" ]; then
    echo -e "\033[0;31m获取归属地位置失败！\033[0m"
    Exit
  fi
  if [ -z "$ipv4" -a -z "$ipv6" ]; then
    echo -e "\033[0;31m获取IP地址失败！\033[0m"
    Exit
  fi
}


Input(){ 
  unset -v server_port
  local sport=$(Rand 1024 65535)
  echo -e "请输入Shadowsocks远程端口 [1-65535]"
  until [ -n "$server_port" ]; do      
    read -p "(默认端口: $(echo -e "\033[0;96m${sport}\033[0m")):" server_port
    [ -z "$server_port" ] && server_port=$sport
    if [[ "$server_port" =~ ^[0-9]+$ ]]; then
      if [ "$server_port" -gt 0 -a "$server_port" -le 65535 -a "${server_port:0:1}" -ne 0 ]; then
        if [ -n "$(netstat -tulpn|grep LISTEN|grep ":$server_port ")" ];then
	  echo "端口 $server_port 被其他进程占用请重新输入"
	  unset -v server_port
	else
	  echo -e "\n\033[1;37m$server_port\033[0m\n"
	fi
      else
        unset -v server_port 
      fi
    else
      unset -v server_port
    fi
  done
  

  echo -e "请输入Shadowsocks密码"
  local ciphertext=$(cat /proc/sys/kernel/random/uuid|base64)
  local spass=${ciphertext:0:12}
  read -p "(默认密码: $(echo -e "\033[0;96m${spass}\033[0m")):" password
  [ -z "$password" ] && password=$spass
  echo -e "\n\033[1;37m$password\033[0m\n"

  echo -e "请选择Shadowsocks加密方式"
  select method in ${common_ciphers[@]}; do
    [ -n "$method" ]&&break
  done
  echo -e "\n\033[1;37m$method\033[0m\n"
}

Obfs(){
  while true; do   
    read -p "需要 simple-obfs 流量混淆插件吗? [y/n]:" libev_obfs
    [ -z "$libev_obfs" ] && libev_obfs=n
    case $libev_obfs in
      y|Y)
          echo
	  unset -v obfs
	  echo -e "请选择Shadowsocks混淆方式"
	  select obfs in ${obfs_libev[@]}; do
            if [ -n "$obfs" ]; then
	      echo -e "\n\033[1;37m$obfs\033[0m\n"
	      break 2
	    fi
	  done
          ;;
      n|N)
          break
          ;;
    esac
  done
}

Status(){
  unset -v stat
  echo -e "服务状态: \c"
  local stat=$(manager-tool ping)
  if [ "${stat:0:4}" = 'stat' ]; then
    echo -e "\033[32m运行中\033[0m"
  else
    echo -e "\033[33m未运行\033[0m"
  fi
}

Check(){
  if [ "$(id -u)" -ne 0 ]; then
   echo -e "\033[33m请使用ROOT用户执行！ \033[0m"
   Exit
  fi
  #kernel_ver=$(cat /proc/version)
  if [ "$(uname -m)" != 'x86_64' ]; then
   echo -e "\033[33m编译文件不支持此平台！感谢你的支持。 \033[0m"
   Exit
  fi
  for x in ss-server ss-manager obfs-server manager-tool; do
    if [ ! -f $DIR/$x ]; then
      echo "文件 $x 没有找到，正在下载..."
      Download $DIR/$x $URL/$x
    fi
    if [ ! -x $DIR/$x ]; then
      echo "文件 $x 没有执行权限，正在添加执行权限..."
      chmod +x $DIR/$x
    fi
    if [ "$x" != "manager-tool" ]; then
      if [[ "$($DIR/$x -h)" != *"by Max Lv"* ]]; then
        echo "可执行文件 $x 运行出错！ "
        rm -f $DIR/$x
        Exit
      fi
    fi
  done
  if [ ! -d $HOME ]; then
    echo "没有找到 $HOME 目录，正在创建文件夹..." 
    mkdir -p $HOME
  fi
  if [ ! -s $ACL_FILE ]; then
    echo "没有找到 $ACL_FILE 文件，正在下载.." 
    Download $ACL_FILE https://github.com/shadowsocks/shadowsocks-libev/raw/master/acl/server_block_local.acl
  fi
  if [ ! -s $CONF_FILE ]; then
    echo "没有找到 $CONF_FILE 配置文件，正在自动配置..."
    Address
    local server_value='0.0.0.0'
    if [ -n "$ipv6" ]; then
      local server_value='["[::0]","0.0.0.0"]'
    fi
    cat >$CONF_FILE<<-EOF
{
  "server": "$server_value",
  "port_password": {
  },
  "timeout": 120,
  "method": "chacha20-ietf-poly1305",
  "nameserver": "8.8.8.8",
  "mode": "tcp_and_udp",
  "reuse_port": true,
  "fast_open": false
}
EOF
  fi
}

Version(){
  echo -e "ACL \033[1;31m$ACL_FILE\033[0m"
  echo -e "HOME \033[1;31m$HOME\033[0m"
  echo -e "PID \033[1;31m$NOW_PID\033[0m"
  echo -e "PORT_FILE \033[1;31m$PORT_FILE\033[0m"
  echo -e "CONF_FILE \033[1;31m$CONF_FILE\033[0m"
  echo -e "ss-server \033[1;31m$(ss-server -h|grep -oE "([0-9]\.){1,2}[0-9]"|head -n 1)\033[0m"
  echo -e "ss-manager \033[1;31m$(ss-manager -h|grep -oE "([0-9]\.){1,2}[0-9]"|head -n 1)\033[0m"
  echo -e "obfs-server \033[1;31m$(obfs-server -h|grep -oE "([0-9]\.){1,2}[0-9]"|head -n 1)\033[0m"
  read -p "请按回车键或 Ctrl + C 退出"
}

Online()(
  local a=$(manager-tool ping)
  local b=${a#stat:\ \{}
  local c=${b%\}}
  IFS=','
  for i in ${c//\"/}; do
    IFS=' ';
    for j in $i; do
      if [ "${j%\:*}" = "$1" ];then
        echo ${j#*\:}|egrep -o '[0-9]+'
      fi
    done
  done
)

List(){
  if [ -s $PORT_FILE ]; then
    echo
    printf "\033[1m%-5s %-7s %-8s %-15s %-10s %-10s %-10s %-10s %-5s\033[0m\n" 序号 端口 密码 加密方式 混淆方式 已用流量 可用流量 使用率 状态
    local sum=0
    #while IFS= read -r line; do
    echo -e "$(cat $PORT_FILE)\n"|while IFS= read -r line; do
      IFS='|'
      for l in $line; do
        case ${l%=*} in
          server_port)
              ((sum++))
              server_port=${l#*=}
              ;;
          password)
              password=${l#*=}
              ;;
          method)
              method=${l#*=}
              ;;
          obfs)
              obfs=${l#*=}
              ;;
          total)
              total=${l#*=}
              ;;
        esac
      done
      if [ -n "$server_port" ]; then
        local used=$(Online $server_port)
        if [ "${used:=-1}" -ge 0 ];then
          local stats='Online'
          local statsc='\033[44;37m%-5s\033[0m'
        else
          local used=0
          local stats='Offline'
          local statsc='\033[41;37m%-5s\033[0m'
        fi

#:<<EOF
        local rate=$(printf "%d" $((used*100/total)))
        if [ "$rate" -le 25 ]; then
          local ratec='\033[44;37m%-5s\033[0m'
        elif [ "$rate" -gt 25 -a "$rate" -le 50 ]; then
          local ratec='\033[42;30m%-5s\033[0m'
        elif [ "$rate" -gt 50 -a "$rate" -le 75 ]; then
          local ratec='\033[43;45m%-5s\033[0m'
        elif [ "$rate" -gt 75 -a "$rate" -lt 100 ]; then
          local ratec='\033[43;30m%-5s\033[0m'
        else
          local ratec='\033[41;37m%-5s\033[0m'
          rate=100
        fi
#EOF    
        printf "%-2s %-5s %-5s %-5s %-5s %-5s %-5s $ratec $statsc\n" $sum $server_port $password $method ${obfs:-无混淆} $((used/1024/1024))/MB $((total/1024/1024))/MB $rate% ${stats:-Offline}
      fi
      unset -v server_port stats
    done
    echo
    #done < $PORT_FILE
  else
    echo -e "\033[0;33m没有找到端口列表文件...\033[0m"
  fi
  read -p "请按回车键或 Ctrl + C 退出"
}

Add(){
  Address
  Input
  Obfs
  local ports=$(Online $server_port)
  if [[ "$ports" =~ ^[0-9]+$ ]]; then
    if [ "$ports" -ge 0 ]; then
      echo "$(Online $server_port) 端口正常使用中，无法添加！删除后重试。"
      Exit
    fi
  fi
  if [ -s $PORT_FILE ]; then
    echo -e "$(cat $PORT_FILE)\n"|while IFS= read -r line; do
      IFS='|'
      for l in $line; do
        if [ "${l#*=}" = "$server_port" ]; then
          echo "端口已存在于端口列表中，请删除后重试。"
          Exit
        fi
      done
    done
  fi
  unset -v total
  until [ -n "$total" ]; do      
    read -p "请输入端口流量配额 (MB) : " total
    if [[ "$total" =~ ^[0-9]+$ ]]; then
      if [ "$total" -gt 0 -a "${total:0:1}" -ne 0 ];then
        echo -e "\n\033[1;37m${total} MB\033[0m\n"
      else
	unset -v total
      fi
    else
      unset -v total
    fi
  done
  clear
  case $libev_obfs in
    y|Y)
        manager-tool "add: {\"server_port\":$server_port, \"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}"
      ;;
    *)
        manager-tool "add: {\"server_port\":$server_port, \"password\":\"$password\",\"method\":\"$method\"}"
      ;;
  esac
  echo "server_port=$server_port|password=$password|method=$method|obfs=$obfs|total=$((total*1024*1024))" >> $PORT_FILE
  if [ -n "$ipv4" ]; then
    echo -e "服务器(IPv4)     : \033[1;31m $ipv4 \033[0m"
    sslink_v4="ss://$(echo -n "$method:$password@$ipv4:$server_port" | base64 -w0)"
  fi
  if [ -n "$ipv6" ]; then
    echo -e "服务器(IPv6)     : \033[1;31m $ipv6 \033[0m"
    sslink_v6="ss://$(echo -n "$method:$password@$ipv6:$server_port" | base64 -w0)"
  fi
  name=$(Urlencode "$addr")
  echo -e "远程端口      : \033[1;31m $server_port \033[0m"
  echo -e "密码      : \033[1;31m $password \033[0m"
  echo -e "加密方式      : \033[1;31m $method \033[0m"
  case ${obfs} in
    http|tls)
      echo -e "obfs流量混淆      : \033[1;31m$obfs \033[0m"
      echo
      tmp="?plugin=$(Urlencode "obfs-local;obfs=$obfs;obfs-host=$OBFS_HOST")"
      if [ -n "$sslink_v4" ]; then
        echo -e "\033[0;32m$sslink_v4$tmp#$name \033[0m"
      fi
      if [ -n "$sslink_v6" ]; then
        echo -e "\033[0;32m$sslink_v6$tmp#$name \033[0m"
      fi
    ;;
    *)
      if [ -n "$sslink_v4" ]; then
        echo -e "\033[0;32m$sslink_v4#$name \033[0m"
      fi
      if [ -n "$sslink_v6" ]; then
        echo -e "\033[0;32m$sslink_v6#$name \033[0m"
      fi
    ;;
    esac
    echo
  local ports=$(Online $server_port)
  if [[ "$ports" =~ ^[0-9]+$ ]]; then
    echo -e "[\033[41;37mFBI WARNING\033[0m]\033[0;33m以上链接信息拿笔记好。此脚本切勿用于翻墙之外的其余用途！！！\033[0m"
  else    
    echo -e "\033[0;31m已添加端口但没有启动成功，请确认是否已 <启动运行> \033[0m"
  fi
  echo 
  read -p "请按回车键或 Ctrl + C 退出"
}

Delete(){  
  if [ -s $PORT_FILE ]; then
    unset -v port
    until [ -n "$port" ]; do
      read -p "请输入需要删除的端口: " port
      if [ "$port" -lt 1 -o "$port" -ge 65535 -o "${port:0:1}" -eq 0 ]; then
	unset -v port
      fi
    done
    touch $PORT_FILE.2
    local sum=0
    echo -e "$(cat $PORT_FILE)\n"|while IFS= read -r line; do
      IFS='|'
      for l in $line; do
        case ${l%=*} in
          server_port)
              server_port=${l#*=}
              ;;
          password)
              password=${l#*=}
              ;;
          method)
              method=${l#*=}
              ;;
          obfs)
              obfs=${l#*=}
              ;;
          total)
              total=${l#*=}
              ;;
        esac
      done
      if [[ "$server_port" -ne "$port" && "$server_port" -gt 0 && "$server_port" -lt 65535 && -n "$password" && -n "$method" && -n "$total" ]]; then
        echo "server_port=$server_port|password=$password|method=$method|obfs=$obfs|total=$total" >> $PORT_FILE.2
      fi
      if [[ "$server_port" -eq "$port" ]]; then
        ((sum++))
        manager-tool "remove: {\"server_port\":$port}"
        if [ -r $HOME/.shadowsocks_$port.pid ]; then
          read PID < $HOME/.shadowsocks_$port.pid
          if [ -d /proc/$PID ]; then
            kill $PID
            rm -f $HOME/.shadowsocks_$port.pid
          fi
        fi
        rm -f $HOME/.shadowsocks_$port.conf      
        echo "累计删除 $sum 条端口记录"
      fi
      unset -v server_port password method obfs total
    done
    mv -f $PORT_FILE.2 $PORT_FILE
  else
    echo -e "\033[0;33m没有找到端口列表文件\033[0m"
  fi
  read -p "请按回车键或 Ctrl + C 退出"
}

Start(){
  if [ -n "$(netstat -tulpn|grep LISTEN|grep ':6000 ')" ];then
    echo "端口 6000 被其他进程占用请关闭占用进程后重试！"
    Exit
  fi
  (setsid ss-manager \
  -c $CONF_FILE \
  --manager-address 127.0.0.1:6000 \
  --executable ss-server \
  --acl $ACL_FILE \
  -D $HOME > /dev/null &)
  if [ -s $PORT_FILE ]; then
    echo -e "$(cat $PORT_FILE)\n"|while IFS= read -r line; do
      IFS='|'
      for l in $line; do
        case ${l%=*} in
          server_port)
              server_port=${l#*=}
              ;;
          password)
              password=${l#*=}
              ;;
          method)
              method=${l#*=}
              ;;
          obfs)
              obfs=${l#*=}
              ;;
          total)
              total=${l#*=}
              ;;
        esac
        if [[ "$(Online $server_port)" -le 0 && "$server_port" -gt 0 && "$server_port" -lt 65535 && -n "$password" && -n "$method" && -n "$obfs" && -n "$total" ]]; then
          echo -e "正在打开\033[32m $server_port \033[0m端口服务 混淆方式 $obfs"
          manager-tool "add: {\"server_port\":$server_port, \"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}"
          unset -v server_port password method obfs total
        fi
        if [[ "$(Online $server_port)" -le 0 && "$server_port" -gt 0 && "$server_port" -lt 65535 && -n "$password" && -n "$method" && -n "$total" ]]; then
          echo -e "正在打开\033[32m $server_port \033[0m端口服务"
          manager-tool "add: {\"server_port\":$server_port, \"password\":\"$password\",\"method\":\"$method\"}"
          unset -v server_port password method obfs total
        fi
      done
    done
  else
    echo -e "\033[0;33m没有找到端口列表文件...\033[0m"
  fi
  read -p "请按回车键或 Ctrl + C 退出"
}

Cull(){
  unset -v portx
  until [ -n "$portx" ]; do
    read -p "请输入需要强制下线的的端口: " portx
    if [ "$portx" -lt 1 -o "$portx" -ge 65535 -o "${portx:0:1}" -eq 0 ]; then
      unset -v portx
    fi
  done
  if [ -r $HOME/.shadowsocks_$portx.pid ]; then
    read PID < $HOME/.shadowsocks_$portx.pid
    if [ -d /proc/$PID ]; then
      kill $PID > /dev/null
      rm -f $HOME/.shadowsocks_$portx.pid
      echo -e "已强制下线端口 \033[33m $portx \033[0m\c"
      manager-tool "remove: {\"server_port\":$portx}"
    else
      echo -e "\033[0;33m没有服务运行在此 $portx 端口\033[0m"
    fi
  else
    echo -e "\033[0;33m没有找到PID文件\033[0m"
  fi
  read -p "请按回车键或 Ctrl + C 退出"
}

Stop(){
  for k in $@; do
    pkill $k
    if [ $? -eq 0 ]; then
      echo -e "\033[32m$k 已被关闭 \033[0m"
    else
      echo -e "\033[33m$k 关闭失败！ \033[0m"
    fi
  done
}

Uninstall(){
  read -p $'\033[31m确定要卸载吗? [y/n]\033[0m' define
  case $define in
    y|Y)
        Stop ss-manager
        rm -rf $HOME
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/obfs-server
        rm -f /usr/local/bin/manager-tool
        rm -f $0
        echo -e "\033[41m已全部卸载干净！\033[0m\nBug反馈: \033[4mhttps://github.com/yiguihai/shadowsocks_install\033[0m"
        echo -e "\033[46m See You ... \033[0m"
        ;;
    *)
        echo -e "\033[32m已取消操作...\033[0m"
        ;;
  esac
    read -p "请按回车键或 Ctrl + C 退出"
    Exit
}

Debug(){
  unset -v sec
  until [ -n "$sec" ]; do
    read -p "请输入循环的时间(秒）: " sec
    if [ "$sec" -le 0 -o "${sec:0:1}" -eq 0 ]; then
      unset -v sec
    fi
  done
  while true; do
    echo -e "$(cat $PORT_FILE)\n"|while IFS= read -r line; do
      IFS='|'
      for l in $line; do
        case ${l%=*} in
          server_port)
              server_port=${l#*=}
              ;;
          password)
              password=${l#*=}
              ;;
          method)
              method=${l#*=}
              ;;
          obfs)
              obfs=${l#*=}
              ;;
          total)
              total=${l#*=}
              ;;
        esac
      done
      flow=$(Online $server_port)
      if [[ -n "$server_port" && "$server_port" -ge 0 && -n "$flow" && "$flow" -ge 0 ]]; then
        if [ "$flow" -ge "$total" ]; then
          echo -e "端口\033[1;31m $server_port \033[0m流量已用完。正在下线.. \c"
          manager-tool "remove: {\"server_port\":$server_port}"
        fi
        echo -e "端口\033[1;31m $server_port \033[0m已使用流量 \033[0;96m$flow\033[0m"
        unset -v flow server_port
      fi
    done
    echo "暂停 $sec 秒后继续监控或 Ctrl + C 退出"
    sleep $sec
  done
}

Exit(){
  kill -9 $NOW_PID
}

while true; do
  Check
  clear
  Author
  Status
cat <<EOF
  1. 端口列表
  2. 启动运行
  3. 停止运行
  4. 添加端口
  5. 删除端口
  6. 强制下线
  7. 监控模式
  8. 卸载删除
  9. 版本信息
EOF
  read -p $'请选择 \e[95m1-9\e[0m: ' action
    case $action in
    1)
        List
        ;;
    2)
        Start
        ;;
    3)
        Stop ss-manager
        ;;
    4)
        Add
        ;;
    5)
        Delete
        ;;
    6)
        Cull
        ;;
    7)
        Debug
        ;;
    8)
        Uninstall
        ;;
    9)
        Version
        ;;
    *)
        break 2
        ;;
  esac
done
