#!/usr/bin/env bash
#
# Auto install Shadowsocks-libev Server
#
# Copyright (C) 2016-2019 Yiguihai <yiguihai@gmail.com>
#
# System Required:  CentOS 7+, Debian8+, Ubuntu14+
#
# Reference URL:
# https://github.com/shadowsocks/shadowsocks
# https://github.com/shadowsocks/shadowsocks-libev
#
# Thanks:
# @clowwindy  <https://twitter.com/clowwindy>
# @madeye     <https://github.com/madeye>
# https://stackoverflow.com/questions/38015239/url-encoding-a-string-in-shell-script-in-a-portable-way
# 
# Intro:  https://github.com/yiguihai
#iptables -t nat -A OUTPUT ! -o lo -p udp --dport 53 -m owner --uid-owner nobody -j DNAT --to-destination 127.0.0.1
export HISTCONTROL=ignorespace
export HISTSIZE=0

DIR='/usr/bin'

white='\033[1;37m'
red='\033[0;31m'
lightred='\033[1;31m'
green='\033[0;32m'
yellow='\033[0;33m'
magenta='\033[0;95m'
cyan='\033[0;96m'
plain='\033[0m'

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/yiguihai/shadowsocks_install/master/shadowsocks-libev-centos"
shadowsocks_libev_debian="https://raw.githubusercontent.com/yiguihai/shadowsocks_install/master/shadowsocks-libev-debian"
server_file_url="https://github.com/yiguihai/shadowsocks_install/raw/master/ss-server"
obfs_file_url="https://github.com/yiguihai/shadowsocks_install/raw/master/obfs-server"

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

# libev obfuscating
obfs_libev=(http tls)

url_list_ipv4=(
ipv4.icanhazip.com
ipinfo.io/ip
ifconfig.me
api.ipify.org
)
#myip.ipip.net
check_sys(){
for i in 'apt' 'yum'; do
  type -f $i > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    release="$i"
    continue
  fi
done
if [[ ${release} == "yum" ]]; then
  if $(type -f 'firewall-cmd' > /dev/null 2>&1); then
    centos_ver=7
  else
    centos_ver=6
  fi
fi
}

urlencodepipe(){
  local LANG=C; local c; while IFS= read -r c; do
    case $c in [a-zA-Z0-9.~_-]) printf "$c"; continue ;; esac
    printf "$c" | od -An -tx1 | tr ' ' % | tr -d '\n'
  done <<EOF
$(fold -w1)
EOF
  echo
}

urlencode()(
  printf "$*"|urlencodepipe;
)

get_rand()(
    min=$1
    max=$(($2-$min+1))
    num=$(($RANDOM+1000000000)) #增加一个10位的数再求余
    echo $(($num%$max+$min))
)

get_ipv4(){
    ipv4=$(ip addr|egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'|egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\."|head -n 1)
    addr=$(wget -qO- -t1 -T2 -U 'curl/7.65.0' cip.cc|grep '地址'|cut -d':' -f2|sed 's/^[ \t]*//g')
    if [[ -z "${ipv4}" ]]; then
      for i in ${url_list_ipv4[@]}; do
        ipv4=$(wget -qO- -t1 -T2 $i)
        if [[ -z "${ipv4}" ]]; then
          unset -v ipv4        
        else
          continue
        fi
      done
    fi
}

get_ipv6(){
    ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
}

download_file()(
    filename=$(basename $1)
    if [[ -f ${1} ]]; then
      echo "${filename} [found]"
    else
      echo "${filename} not found, download now..."
      wget --no-check-certificate -q -c -t3 -T60 -O ${1} ${2}
      if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Download ${filename} failed."
        exit 1
      fi
      chmod +x ${1}
    fi
)

install_prepare_shadowsocks(){
    unset -v server_port
    local sport=$(get_rand 1024 65535)
    echo -e "请输入Shadowsocks远程端口 [1-65535]"
    until [[ $server_port ]]; do      
      read -p "(默认端口: $(echo -e "${cyan}${sport}${plain}")):" server_port
      [ -z "${server_port}" ] && server_port=${sport}
      if [ ${server_port} -le 1 ] || [ ${server_port} -ge 65535 ] || [ ${server_port:0:1} = 0 ]; then
        server_port=${sport}
      fi
    done
    echo -e "\n${white}${server_port}${plain}\n"
    
    unset -v password
    echo -e "请输入Shadowsocks密码"
    local spass=$(cat /proc/sys/kernel/random/uuid|base64)
    read -p "(默认密码: $(echo -e "${cyan}${spass}${plain}")):" password
    [ -z "${password}" ] && password=${spass}
    echo -e "\n${white}${password}${plain}\n"
    
    unset -v method
    echo -e "请选择Shadowsocks加密方式"
    select method in ${common_ciphers[@]}; do
      [ $method ]&&break
    done
    echo -e "\n${white}${method}${plain}\n"
    
    download_file "${DIR}/ss-server" ${server_file_url}
    local service_name=$(basename ${shadowsocks_libev_init})
    case ${release} in
        apt)
        download_file ${shadowsocks_libev_init} ${shadowsocks_libev_debian}
        update-rc.d -f ${service_name} defaults
        ;;
        yum)
        download_file ${shadowsocks_libev_init} ${shadowsocks_libev_centos}
        chkconfig --add ${service_name}
        chkconfig ${service_name} on
        ;;
    esac
}

install_prepare_obfs(){
    echo -e "需要安装 simple-obfs 流量混淆插件吗? [y/n]"
    while true
    do   
    read -p "(默认: n):" libev_obfs
    [ -z "$libev_obfs" ] && libev_obfs=n
    case "${libev_obfs}" in
        y|Y|n|N)
        break
        ;;
        *)
        echo -e "[${red}错误${plain}] 请输入 [y/n]"
        ;;
    esac
    done
    echo -e "\n${white}${libev_obfs}${plain}\n"

    case "${libev_obfs}" in
        y|Y)
        unset -v obfs
        echo -e "请选择Shadowsocks混淆方式"
        select obfs in ${obfs_libev[@]}; do
          [ $obfs ]&&break
        done
        echo -e "\n${white}${obfs}${plain}\n" 
        download_file "${DIR}/obfs-server" ${obfs_file_url}
        ;;
    esac
}

config_shadowsocks()(
    server_value="\"0.0.0.0\""
    
    if [ "${ipv6}" ]; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    #ver=$(uname -r)
    #echo "${ver:0:3}    

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_libev_config})
    fi

    if [[ "${libev_obfs}" == "y" ]] || [[ "${libev_obfs}" == "Y" ]]; then
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${server_port},
    "password":"${password}",
    "timeout":300,
    "user":"nobody",
    "method":"${method}",
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${obfs}",
    "fast_open":false
}
EOF
    else
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${server_port},
    "password":"${password}",
    "timeout":300,
    "user":"nobody",
    "method":"${method}",
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "fast_open":false
}
EOF
    fi
)

config_firewall()(
  if [[ ${release} == "yum" ]]; then
    case "${centos_ver}" in
        7)
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            default_zone=$(firewall-cmd --get-default-zone)
            firewall-cmd --permanent --zone=${default_zone} --add-port=${server_port}/tcp
            firewall-cmd --permanent --zone=${default_zone} --add-port=${server_port}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${server_port} manually if necessary."
        fi
        ;;
        *)
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${server_port} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${server_port} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${server_port} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] port ${green}${server_port}${plain} already be enabled."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${server_port} manually if necessary."
        fi
        ;;
    esac
  fi
)

install_completed_libev()(
    ${shadowsocks_libev_init} start
    name=$(urlencode "${addr}")
    echo
    echo -e "Congratulations, ${green}Shadowsocks-libev${plain} ${lightred}$(ss-server -h|grep -oE "([0-9]\.){1,2}[0-9]"|head -n 1)${plain} server install completed!"    
    if [ "${ipv4}" ]; then
      echo -e "Your Server IPv4      : ${red} ${ipv4} ${plain}"
      qr_code_v4="ss://$(echo -n "${method}:${password}@${ipv4}:${server_port}" | base64 -w0)"      
    fi
    if [ "${ipv6}" ]; then
      echo -e "Your Server IPv6      : ${red} ${ipv6} ${plain}"
      qr_code_v6="ss://$(echo -n "${method}:${password}@${ipv6}:${server_port}" | base64 -w0)"
    fi
    echo -e "Your Server Port      : ${red} ${server_port} ${plain}"
    echo -e "Your Password         : ${red} ${password} ${plain}"
    echo -e "Your Encryption Method: ${red} ${method} ${plain}"    
    case "${obfs}" in
    http|tls)
      echo -e "Your obfs             : ${red} ${obfs} ${plain}"
      echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
      tmp="?plugin=$(urlencode "obfs-local;obfs=$obfs;obfs-host=www.bing.com")"
      if [ "${qr_code_v4}" ]; then
        echo -e "${green} ${qr_code_v4}${tmp}#${name} ${plain}"
      fi
      if [ "${qr_code_v6}" ]; then
        echo -e "${green} ${qr_code_v6}${tmp}#${name} ${plain}"
      fi
    ;;
    *)
      echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
      if [ "${qr_code_v4}" ]; then
        echo -e "${green} ${qr_code_v4}#${name} ${plain}"
      fi
      if [ "${qr_code_v6}" ]; then
        echo -e "${green} ${qr_code_v6}#${name} ${plain}"
      fi
    ;;
    esac
    echo 
    echo -e "[${red}FBI WARNING${plain}]${yellow}以上链接信息拿笔记好。此脚本切勿用于翻墙之外的其余用途！！！${plain}"
)

install_shadowsocks()(
  check_sys
  get_ipv4
  get_ipv6
  install_prepare_shadowsocks  
  install_prepare_obfs
  config_shadowsocks
  config_firewall
  history -cw
  clear
  install_completed_libev
)

uninstall_shadowsocks_libev()(
    echo -e "Are you sure uninstall ${red}Shadowsocks-libev${plain}? [y/n]\n"
    read -p "(default: n):" answer
    case "${answer}" in
      y|Y)
        ${shadowsocks_libev_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
          ${shadowsocks_libev_init} stop
        fi
        service_name=$(basename ${shadowsocks_libev_init})
        case ${release} in
        apt)
          update-rc.d -f ${service_name} remove
        ;;
        yum)
          chkconfig --del ${service_name}
        ;;
        esac
        sleep 0.5
        rm -fr $(dirname ${shadowsocks_libev_config})
        rm -f ${DIR}/ss-server
        rm -f ${DIR}/obfs-server
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}Info${plain}] Shadowsocks-libev uninstall success"
      ;;
      n|N)
        echo
        echo -e "[${green}Info${plain}] ${software[3]} uninstall cancelled, nothing to do..."
        echo
      ;;
    esac
)

uninstall_shadowsocks()(
  if [ -f ${shadowsocks_libev_init} ]; then
    check_sys
    uninstall_shadowsocks_libev
  else
    echo -e "[${red}Error${plain}] Shadowsocks-libev not installed, please check it and try again."
    echo
    exit 1
  fi
)

# Initialization step
action=$1
[ -z $1 ] && action=install
case "${action}" in
    install|uninstall)
        ${action}_shadowsocks
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: $(basename $0) [install|uninstall]"
        ;;
esac
