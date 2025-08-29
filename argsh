#!/bin/sh
export LANG=en_US.UTF-8
[ -z "${vlpt+x}" ] || vlp=yes
[ -z "${vmpt+x}" ] || { vmp=yes; vmag=yes; } 
[ -z "${hypt+x}" ] || hyp=yes
[ -z "${tupt+x}" ] || tup=yes
[ -z "${xhpt+x}" ] || xhp=yes
[ -z "${anpt+x}" ] || anp=yes
[ -z "${sspt+x}" ] || ssp=yes
[ -z "${arpt+x}" ] || arp=yes
[ -z "${warp+x}" ] || wap=yes
if find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -Eq 'agsb/(s|x)' || pgrep -f 'agsb/(s|x)' >/dev/null 2>&1; then
if [ "$1" = "rep" ]; then
[ "$ssp" = yes ] || [ "$vlp" = yes ] || [ "$vmp" = yes ] || [ "$hyp" = yes ] || [ "$tup" = yes ] || [ "$xhp" = yes ] || [ "$anp" = yes ] || [ "$arp" = yes ] || { echo "提示：重置协议参数有误，请自查！💣"; exit; }
fi
else
[ "$1" = "del" ] || [ "$ssp" = yes ] || [ "$vlp" = yes ] || [ "$vmp" = yes ] || [ "$hyp" = yes ] || [ "$tup" = yes ] || [ "$xhp" = yes ] || [ "$anp" = yes ] || [ "$arp" = yes ] || { echo "提示：未安装ArgoSB脚本，请在脚本前至少设置一个协议变量哦，再见！💣"; exit; }
fi
export uuid=${uuid:-''}
export port_vl_re=${vlpt:-''}
export port_vm_ws=${vmpt:-''}
export port_hy2=${hypt:-''}
export port_tu=${tupt:-''}
export port_xh=${xhpt:-''}
export port_an=${anpt:-''}
export port_ar=${arpt:-''}
export port_ss=${sspt:-''}
export ym_vl_re=${reym:-''}
export cdnym=${cdnym:-''}
export argo=${argo:-''}
export ARGO_DOMAIN=${agn:-''}
export ARGO_AUTH=${agk:-''}
export ippz=${ippz:-''}
export ipyx=${ipyx:-''}
export warp=${warp:-''}
export name=${name:-''}
showmode(){
echo "ArgoSB脚本项目地址：https://github.com/yonggekkk/ArgoSB"
echo "主脚本：bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/argosb/main/argosb.sh)"
echo "显示节点信息命令：agsb list 【或者】 主脚本 list"
echo "更换代理协议变量组命令：自定义各种协议变量组 agsb rep 【或者】 自定义各种协议变量组 主脚本 rep"
echo "重启脚本命令：agsb res 【或者】 主脚本 res"
echo "卸载脚本命令：agsb del 【或者】 主脚本 del"
echo "双栈VPS显示IPv4节点配置命令：ippz=4 agsb list 【或者】 ippz=4 主脚本 list"
echo "双栈VPS显示IPv6节点配置命令：ippz=6 agsb list 【或者】 ippz=6 主脚本 list"
echo "---------------------------------------------------------"
echo
}
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "甬哥Github项目 ：github.com/yonggekkk"
echo "甬哥Blogger博客 ：ygkkk.blogspot.com"
echo "甬哥YouTube频道 ：www.youtube.com/@ygkkk"
echo "ArgoSB一键无交互小钢炮脚本💣"
echo "当前版本：V25.8.21"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
hostname=$(uname -a | awk '{print $2}')
op=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty_name | cut -d \" -f2)
[ -z "$(systemd-detect-virt 2>/dev/null)" ] && vi=$(virt-what 2>/dev/null) || vi=$(systemd-detect-virt 2>/dev/null)
case $(uname -m) in
aarch64) cpu=arm64;;
x86_64) cpu=amd64;;
*) echo "目前脚本不支持$(uname -m)架构" && exit
esac
mkdir -p "$HOME/agsb"
warpcheck(){
wgcfv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
wgcfv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
}
v4v6(){
v4=$(curl -s4m5 icanhazip.com -k)
v6=$(curl -s6m5 icanhazip.com -k)
}
warpsx(){
if [ -n "$name" ]; then
sxname=$name-
echo "$sxname" > "$HOME/agsb/name"
echo
echo "所有节点名称前缀：$name"
fi
v4v6
if echo "$v6" | grep -q '^2a09' || echo "$v4" | grep -q '^104.28'; then
xouttag=direct
souttag=direct
wap=warpargo
echo
echo "请注意：你已安装了warp"
else
if [ "$wap" != yes ]; then
xouttag=direct
souttag=direct
wap=warpargo
elif [ "$warp" = "" ]; then
xouttag=warp-out
souttag=warp-out
wap=warp
echo
echo "所有内核协议添加warp全局出站"
elif [ "$warp" = "x" ]; then
xouttag=warp-out
souttag=direct
wap=warp
echo
echo "Xray内核的协议添加warp全局出站"
elif [ "$warp" = "s" ]; then
xouttag=direct
souttag=warp-out
wap=warp
echo
echo "Sing-box内核的协议添加warp全局出站"
else
xouttag=direct
souttag=direct
wap=warpargo
fi
fi
if [ "$ipyx" = "" ]; then
xrip='ForceIP'
sbip='prefer_ipv6'
echo
elif [ "$ipyx" = "64" ]; then
xrip='ForceIPv6v4'
sbip='prefer_ipv6'
echo
echo "所有节点IPV6优先"
elif [ "$ipyx" = "46" ]; then
xrip='ForceIPv4v6'
sbip='prefer_ipv4'
echo
echo "所有节点IPV4优先"
elif [ "$ipyx" = "6" ]; then
xrip='ForceIPv6'
sbip='ipv6_only'
echo
echo "所有节点仅IPV6"
elif [ "$ipyx" = "4" ]; then
xrip='ForceIPv4'
sbip='ipv4_only'
echo
echo "所有节点仅IPV4"
else
xrip='ForceIP'
sbip='prefer_ipv6'
echo
fi
}
insuuid(){
if [ -z "$uuid" ] && [ ! -e "$HOME/agsb/uuid" ]; then
if [ -e "$HOME/agsb/sing-box" ]; then
uuid=$("$HOME/agsb/sing-box" generate uuid)
else
uuid=$("$HOME/agsb/xray" uuid)
fi
echo "$uuid" > "$HOME/agsb/uuid"
elif [ -n "$uuid" ]; then
echo "$uuid" > "$HOME/agsb/uuid"
fi
uuid=$(cat "$HOME/agsb/uuid")
echo "UUID密码：$uuid"
}
installxray(){
echo
echo "=========启用xray内核========="
if [ ! -e "$HOME/agsb/xray" ]; then
curl -Lo "$HOME/agsb/xray" -# --retry 2 https://github.com/yonggekkk/ArgoSB/releases/download/argosbx/xray-$cpu
chmod +x "$HOME/agsb/xray"
sbcore=$("$HOME/agsb/xray" version 2>/dev/null | awk '/^Xray/{print $2}')
echo "已安装Xray正式版内核：$sbcore"
fi
cat > "$HOME/agsb/xr.json" <<EOF
{
  "log": {
    "access": "/dev/null",
    "error": "/dev/null",
    "loglevel": "none"
  },
  "inbounds": [
EOF
insuuid
if [ -n "$xhp" ] || [ -n "$vlp" ]; then
if [ -z "$ym_vl_re" ]; then
ym_vl_re=www.yahoo.com
fi
echo "$ym_vl_re" > "$HOME/agsb/ym_vl_re"
echo "Reality域名：$ym_vl_re"
mkdir -p "$HOME/agsb/xrk"
if [ ! -e "$HOME/agsb/xrk/private_key" ]; then
key_pair=$("$HOME/agsb/xray" x25519)
private_key=$(echo "$key_pair" | head -1 | awk '{print $3}')
public_key=$(echo "$key_pair" | tail -n 1 | awk '{print $3}')
short_id=$(date +%s%N | sha256sum | cut -c 1-8)
echo "$private_key" > "$HOME/agsb/xrk/private_key"
echo "$public_key" > "$HOME/agsb/xrk/public_key"
echo "$short_id" > "$HOME/agsb/xrk/short_id"
fi
private_key_x=$(cat "$HOME/agsb/xrk/private_key")
public_key_x=$(cat "$HOME/agsb/xrk/public_key")
short_id_x=$(cat "$HOME/agsb/xrk/short_id")
fi
if [ -n "$xhp" ]; then
xhp=xhpt
if [ -z "$port_xh" ] && [ ! -e "$HOME/agsb/port_xh" ]; then
port_xh=$(shuf -i 10000-65535 -n 1)
echo "$port_xh" > "$HOME/agsb/port_xh"
elif [ -n "$port_xh" ]; then
echo "$port_xh" > "$HOME/agsb/port_xh"
fi
port_xh=$(cat "$HOME/agsb/port_xh")
echo "Vless-xhttp-reality端口：$port_xh"
cat >> "$HOME/agsb/xr.json" <<EOF
    {
      "tag":"xhttp-reality",
      "listen": "::",
      "port": ${port_xh},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "target": "${ym_vl_re}:443",
          "serverNames": [
            "${ym_vl_re}"
          ],
          "privateKey": "$private_key_x",
          "shortIds": ["$short_id_x"]
        },
        "xhttpSettings": {
          "host": "",
          "path": "${uuid}-xh",
          "mode": "auto"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": false
      }
    },
EOF
else
xhp=xhptargo
fi
if [ -n "$vlp" ]; then
vlp=vlpt
if [ -z "$port_vl_re" ] && [ ! -e "$HOME/agsb/port_vl_re" ]; then
port_vl_re=$(shuf -i 10000-65535 -n 1)
echo "$port_vl_re" > "$HOME/agsb/port_vl_re"
elif [ -n "$port_vl_re" ]; then
echo "$port_vl_re" > "$HOME/agsb/port_vl_re"
fi
port_vl_re=$(cat "$HOME/agsb/port_vl_re")
echo "Vless-reality-vision端口：$port_vl_re"
cat >> "$HOME/agsb/xr.json" <<EOF
        {
            "tag":"reality-vision",
            "listen": "::",
            "port": $port_vl_re,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "dest": "${ym_vl_re}:443",
                    "serverNames": [
                      "${ym_vl_re}"
                    ],
                    "privateKey": "$private_key_x",
                    "shortIds": ["$short_id_x"]
                }
            },
          "sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls", "quic"],
          "metadataOnly": false
      }
    },  
EOF
else
vlp=vlptargo
fi
if [ -n "$ssp" ]; then
ssp=sspt
if [ ! -e "$HOME/agsb/sskey" ]; then
sskey=$(head -c 16 /dev/urandom | base64 -w0)
echo "$sskey" > "$HOME/agsb/sskey"
fi
if [ -z "$port_ss" ] && [ ! -e "$HOME/agsb/port_ss" ]; then
port_ss=$(shuf -i 10000-65535 -n 1)
echo "$port_ss" > "$HOME/agsb/port_ss"
elif [ -n "$port_ss" ]; then
echo "$port_ss" > "$HOME/agsb/port_ss"
fi
sskey=$(cat "$HOME/agsb/sskey")
port_ss=$(cat "$HOME/agsb/port_ss")
echo "Shadowsocks-2022端口：$port_ss"
cat >> "$HOME/agsb/xr.json" <<EOF
        {
            "tag":"ss-2022",
            "listen": "::",
            "port": $port_ss,
            "protocol": "shadowsocks",
                "settings": {
                "method": "2022-blake3-aes-128-gcm",
                "password": "$sskey",
                "network": "tcp,udp"
        },
          "sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls", "quic"],
          "metadataOnly": false
      }
    },  
EOF
else
ssp=ssptargo
fi
}

installsb(){
echo
echo "=========启用Sing-box内核========="
if [ ! -e "$HOME/agsb/sing-box" ]; then
curl -Lo "$HOME/agsb/sing-box" -# --retry 2 https://github.com/yonggekkk/ArgoSB/releases/download/argosbx/sing-box-$cpu
chmod +x "$HOME/agsb/sing-box"
sbcore=$("$HOME/agsb/sing-box" version 2>/dev/null | awk '/version/{print $NF}')
echo "已安装Sing-box正式版内核：$sbcore"
fi
cat > "$HOME/agsb/sb.json" <<EOF
{
"log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
EOF
insuuid
command -v openssl >/dev/null 2>&1 && openssl ecparam -genkey -name prime256v1 -out "$HOME/agsb/private.key" >/dev/null 2>&1
command -v openssl >/dev/null 2>&1 && openssl req -new -x509 -days 36500 -key "$HOME/agsb/private.key" -out "$HOME/agsb/cert.pem" -subj "/CN=www.bing.com" >/dev/null 2>&1
if [ ! -f "$HOME/agsb/private.key" ]; then
curl -Lso "$HOME/agsb/private.key" https://github.com/yonggekkk/ArgoSB/releases/download/argosbx/private.key
curl -Lso "$HOME/agsb/cert.pem" https://github.com/yonggekkk/ArgoSB/releases/download/argosbx/cert.pem
fi
if [ -n "$hyp" ]; then
hyp=hypt
if [ -z "$port_hy2" ] && [ ! -e "$HOME/agsb/port_hy2" ]; then
port_hy2=$(shuf -i 10000-65535 -n 1)
echo "$port_hy2" > "$HOME/agsb/port_hy2"
elif [ -n "$port_hy2" ]; then
echo "$port_hy2" > "$HOME/agsb/port_hy2"
fi
port_hy2=$(cat "$HOME/agsb/port_hy2")
echo "Hysteria2端口：$port_hy2"
cat >> "$HOME/agsb/sb.json" <<EOF
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "listen": "::",
        "listen_port": ${port_hy2},
        "users": [
            {
                "password": "${uuid}"
            }
        ],
        "ignore_client_bandwidth":false,
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "$HOME/agsb/cert.pem",
            "key_path": "$HOME/agsb/private.key"
        }
    },
EOF
else
hyp=hyptargo
fi
if [ -n "$tup" ]; then
tup=tupt
if [ -z "$port_tu" ] && [ ! -e "$HOME/agsb/port_tu" ]; then
port_tu=$(shuf -i 10000-65535 -n 1)
echo "$port_tu" > "$HOME/agsb/port_tu"
elif [ -n "$port_tu" ]; then
echo "$port_tu" > "$HOME/agsb/port_tu"
fi
port_tu=$(cat "$HOME/agsb/port_tu")
echo "Tuic端口：$port_tu"
cat >> "$HOME/agsb/sb.json" <<EOF
        {
            "type":"tuic",
            "tag": "tuic5-sb",
            "listen": "::",
            "listen_port": ${port_tu},
            "users": [
                {
                    "uuid": "${uuid}",
                    "password": "${uuid}"
                }
            ],
            "congestion_control": "bbr",
            "tls":{
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "$HOME/agsb/cert.pem",
                "key_path": "$HOME/agsb/private.key"
            }
        },
EOF
else
tup=tuptargo
fi
if [ -n "$anp" ]; then
anp=anpt
if [ -z "$port_an" ] && [ ! -e "$HOME/agsb/port_an" ]; then
port_an=$(shuf -i 10000-65535 -n 1)
echo "$port_an" > "$HOME/agsb/port_an"
elif [ -n "$port_an" ]; then
echo "$port_an" > "$HOME/agsb/port_an"
fi
port_an=$(cat "$HOME/agsb/port_an")
echo "Anytls端口：$port_an"
cat >> "$HOME/agsb/sb.json" <<EOF
        {
            "type":"anytls",
            "tag":"anytls-sb",
            "listen":"::",
            "listen_port":${port_an},
            "users":[
                {
                  "password":"${uuid}"
                }
            ],
            "padding_scheme":[],
            "tls":{
                "enabled": true,
                "certificate_path": "$HOME/agsb/cert.pem",
                "key_path": "$HOME/agsb/private.key"
            }
        },
EOF
else
anp=anptargo
fi
if [ -n "$arp" ]; then
arp=arpt
if [ -z "$ym_vl_re" ]; then
ym_vl_re=www.yahoo.com
fi
echo "$ym_vl_re" > "$HOME/agsb/ym_vl_re"
echo "Reality域名：$ym_vl_re"
mkdir -p "$HOME/agsb/sbk"
if [ ! -e "$HOME/agsb/sbk/private_key" ]; then
key_pair=$("$HOME/agsb/sing-box" generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
short_id=$("$HOME/agsb/sing-box" generate rand --hex 4)
echo "$private_key" > "$HOME/agsb/sbk/private_key"
echo "$public_key" > "$HOME/agsb/sbk/public_key"
echo "$short_id" > "$HOME/agsb/sbk/short_id"
fi
private_key_s=$(cat "$HOME/agsb/sbk/private_key")
public_key_s=$(cat "$HOME/agsb/sbk/public_key")
short_id_s=$(cat "$HOME/agsb/sbk/short_id")
if [ -z "$port_ar" ] && [ ! -e "$HOME/agsb/port_ar" ]; then
port_ar=$(shuf -i 10000-65535 -n 1)
echo "$port_ar" > "$HOME/agsb/port_ar"
elif [ -n "$port_ar" ]; then
echo "$port_ar" > "$HOME/agsb/port_ar"
fi
port_ar=$(cat "$HOME/agsb/port_ar")
echo "Any-Reality端口：$port_ar"
cat >> "$HOME/agsb/sb.json" <<EOF
        {
            "type":"anytls",
            "tag":"anyreality-sb",
            "listen":"::",
            "listen_port":${port_ar},
            "users":[
                {
                  "password":"${uuid}"
                }
            ],
            "padding_scheme":[],
            "tls": {
            "enabled": true,
            "server_name": "${ym_vl_re}",
             "reality": {
              "enabled": true,
              "handshake": {
              "server": "${ym_vl_re}",
              "server_port": 443
             },
             "private_key": "$private_key_s",
             "short_id": ["$short_id_s"]
            }
          }
        },
EOF
else
arp=arptargo
fi
}

xrsbvm(){
if [ -n "$vmp" ]; then
vmp=vmpt
if [ -z "$port_vm_ws" ] && [ ! -e "$HOME/agsb/port_vm_ws" ]; then
port_vm_ws=$(shuf -i 10000-65535 -n 1)
echo "$port_vm_ws" > "$HOME/agsb/port_vm_ws"
elif [ -n "$port_vm_ws" ]; then
echo "$port_vm_ws" > "$HOME/agsb/port_vm_ws"
fi
port_vm_ws=$(cat "$HOME/agsb/port_vm_ws")
echo "Vmess-ws端口：$port_vm_ws"
if [ -n "$cdnym" ]; then
echo "$cdnym" > "$HOME/agsb/cdnym"
echo "80系CDN或者回源CDN的host域名 (确保IP已解析在CF域名)：$cdnym"
fi
if [ -e "$HOME/agsb/xray" ]; then
cat >> "$HOME/agsb/xr.json" <<EOF
        {
            "tag": "vmess-xr",
            "listen": "::",
            "port": ${port_vm_ws},
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                  "path": "${uuid}-vm"
            }
        },
            "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": false
            }
         }, 
EOF