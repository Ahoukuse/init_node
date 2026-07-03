#!/usr/bin/env bash
#
# 交互式节点部署脚本：VLESS(REALITY+Vision / XHTTP+TLS 过 CDN) + Hysteria2
# 菜单三项：1) REALITY+Vision  2) XHTTP+TLS+CF  3) Hysteria2；选 1/2 自动装 Xray，选 3 自动装 Hysteria2，装完即打印 URI。
#
# 设计不变量（本会话中反复验证过的正确性约束，脚本已内置，请勿手改破坏）：
#   1. XHTTP 入站不带 flow；flow=xtls-rprx-vision 仅属于裸 TCP 的 Vision。
#   2. 两个 VLESS 入站共用同一个 UUID、同一套 REALITY 密钥（持久化在 state 文件）。
#   3. Hysteria2 服务端不写 bandwidth —— 由客户端 up/down 触发 Brutal 拥塞控制。
#   4. Hysteria2 开 salamander 混淆，TLS 握手被打乱不上链路，自签证书即可。
#   5. 2053(CDN) 只放行 Cloudflare 网段，防止源站被直接扫描。
#   6. 客户端与服务端 Xray 版本必须一致（XHTTP 对版本敏感）。
#
# 用法： sudo bash setup-nodes.sh
#
set -euo pipefail

# ----------------------------- 路径与常量 -----------------------------
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_CERT_DIR="/usr/local/etc/xray/cert"
HY_CONFIG="/etc/hysteria/config.yaml"
HY_CERT="/etc/hysteria/server.crt"
HY_KEY="/etc/hysteria/server.key"
STATE_DIR="/etc/vless-hy2"
STATE="${STATE_DIR}/state.env"

TAG_VISION="vless-reality-vision"
TAG_XHTTP_CDN="vless-xhttp-tls-cdn"

PORT_VISION=443
PORT_XHTTP_CDN=2053
PORT_HY=443            # UDP，与 TCP 443 互不冲突

# 变量（会被 state 覆盖）
SERVER_IP=""; UUID=""; REALITY_PRIV=""; REALITY_PUB=""; SHORT_ID=""
REALITY_SNI="www.nvidia.com"; CDN_DOMAIN=""
HY_AUTH_PASS=""; HY_OBFS_PASS=""; HY_MASQ="www.bing.com"

# ----------------------------- 基础工具 -----------------------------
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }
die(){ red "错误：$*"; exit 1; }

require_root(){ [ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash $0"; }

install_deps(){
  local need=()
  command -v jq >/dev/null    || need+=(jq)
  command -v openssl >/dev/null || need+=(openssl)
  command -v curl >/dev/null   || need+=(curl)
  if [ "${#need[@]}" -gt 0 ]; then
    ylw "安装依赖：${need[*]}"
    apt-get update -y && apt-get install -y "${need[@]}"
  fi
  command -v qrencode >/dev/null || apt-get install -y qrencode >/dev/null 2>&1 || true
}

detect_ip(){
  [ -n "$SERVER_IP" ] && return 0
  SERVER_IP="$(curl -fsS4 https://api.ipify.org 2>/dev/null || curl -fsS https://ifconfig.me 2>/dev/null || true)"
  read -rp "服务器公网 IP [${SERVER_IP}]： " _ip
  [ -n "${_ip:-}" ] && SERVER_IP="$_ip"
  [ -n "$SERVER_IP" ] || die "未取得服务器 IP"
}

# ----------------------------- 状态持久化 -----------------------------
# shellcheck source=/dev/null
load_state(){ [ -f "$STATE" ] && . "$STATE" || true; }
save_state(){
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  cat > "$STATE" <<EOF
SERVER_IP="${SERVER_IP}"
UUID="${UUID}"
REALITY_PRIV="${REALITY_PRIV}"
REALITY_PUB="${REALITY_PUB}"
SHORT_ID="${SHORT_ID}"
REALITY_SNI="${REALITY_SNI}"
CDN_DOMAIN="${CDN_DOMAIN}"
HY_AUTH_PASS="${HY_AUTH_PASS}"
HY_OBFS_PASS="${HY_OBFS_PASS}"
HY_MASQ="${HY_MASQ}"
EOF
  chmod 600 "$STATE"
}

# 生成/复用 VLESS 三节点共用的 UUID 与 REALITY 密钥
ensure_common_creds(){
  command -v xray >/dev/null || die "请先执行菜单 1 安装 Xray"
  if [ -z "$UUID" ]; then UUID="$(xray uuid)"; fi
  if [ -z "$REALITY_PRIV" ] || [ -z "$REALITY_PUB" ]; then
    local out; out="$(xray x25519)"
    REALITY_PRIV="$(printf '%s\n' "$out" | grep -iE 'private' | awk '{print $NF}')"
    REALITY_PUB="$(printf '%s\n' "$out"  | grep -iE 'public|password' | awk '{print $NF}')"
  fi
  [ -z "$SHORT_ID" ] && SHORT_ID="$(openssl rand -hex 8)"
  read -rp "REALITY 伪装域名 SNI [${REALITY_SNI}]： " _s; [ -n "${_s:-}" ] && REALITY_SNI="$_s"
  save_state
}

# ----------------------------- Xray 配置管理 -----------------------------
ensure_xray_config(){
  mkdir -p "$(dirname "$XRAY_CONFIG")"
  # 文件缺失、为空或非合法 JSON：用干净骨架初始化
  if [ ! -s "$XRAY_CONFIG" ] || ! jq -e . "$XRAY_CONFIG" >/dev/null 2>&1; then
    cat > "$XRAY_CONFIG" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
    return 0
  fi
  # 已是合法 JSON（可能是安装器写入的默认配置，缺 inbounds 数组）：备份后规整为数组
  cp -a "$XRAY_CONFIG" "${XRAY_CONFIG}.bak.$(date +%s)"
  local tmp; tmp="$(mktemp)"
  jq '.log = (.log // {"loglevel":"warning"})
      | .inbounds  = (if (.inbounds|type)  == "array" then .inbounds else [] end)
      | .outbounds = (if (.outbounds|type) == "array" and ((.outbounds|length) > 0)
                      then .outbounds else [ {"protocol":"freedom","tag":"direct"} ] end)' \
     "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
}

# 按 tag 幂等地增/替换一个 inbound；其它 tag 的入站原样保留
xray_put_inbound(){
  local tag="$1" nb="$2" tmp
  # 端口占用检查：若同端口被“别的 tag”占用则提示
  local port; port="$(printf '%s' "$nb" | jq -r '.port')"
  local clash; clash="$(jq -r --arg t "$tag" --argjson p "$port" \
      '[ (.inbounds // [])[] | select(.port==$p and .tag!=$t) | .tag ] | join(",")' "$XRAY_CONFIG")"
  if [ -n "$clash" ]; then
    ylw "注意：端口 ${port} 已被入站「${clash}」占用，继续将与之共存/冲突。"
    read -rp "仍要继续？[y/N]： " a; [ "${a:-N}" = "y" ] || return 1
  fi
  tmp="$(mktemp)"
  jq --arg tag "$tag" --argjson nb "$nb" \
     '.inbounds = ([ (.inbounds // [])[] | select(.tag != $tag) ] + [$nb])' \
     "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
}

xray_validate_restart(){
  xray run -test -config "$XRAY_CONFIG" || die "Xray 配置校验失败，已保留备份，请检查"
  systemctl restart xray
  systemctl --no-pager -l status xray | head -n 5 || true
}

# ----------------------------- 防火墙 -----------------------------
ufw_active(){ command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; }

open_port(){ # port proto
  local p="$1" proto="$2"
  ufw_active && ufw allow "${p}/${proto}" >/dev/null 2>&1 || true
  ylw "已尝试放行 ${p}/${proto}（云厂商安全组请自行同步放行）"
}

open_port_cf_only(){ # 仅放行 Cloudflare 网段到 2053/tcp
  local p="$1" ip
  if ufw_active; then
    for ip in $(curl -fsS https://www.cloudflare.com/ips-v4 2>/dev/null); do
      ufw allow from "$ip" to any port "$p" proto tcp >/dev/null 2>&1 || true
    done
    grn "已把 ${p}/tcp 限制为仅 Cloudflare IPv4 网段"
  else
    ylw "未检测到活动的 ufw；请手动在安全组把 ${p}/tcp 限制为 Cloudflare 网段"
  fi
}

# ----------------------------- 安装组件 -----------------------------
install_xray(){
  ylw "安装/更新 Xray-core（客户端务必装同一版本）"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  xray version | head -n1
}

install_hysteria(){
  ylw "安装/更新 Hysteria2"
  bash <(curl -fsSL https://get.hy2.sh/)
}

ensure_xray_installed(){ command -v xray >/dev/null || install_xray; }
ensure_hysteria_installed(){ [ -x /usr/local/bin/hysteria ] || command -v hysteria >/dev/null || install_hysteria; }

# ----------------------------- 节点：VLESS REALITY + Vision (443) -----------------------------
setup_vision(){
  ensure_xray_installed
  ensure_xray_config; ensure_common_creds
  local nb; nb="$(cat <<EOF
{
  "tag": "${TAG_VISION}",
  "listen": "0.0.0.0",
  "port": ${PORT_VISION},
  "protocol": "vless",
  "settings": {
    "clients": [ { "id": "${UUID}", "flow": "xtls-rprx-vision" } ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${REALITY_SNI}:443",
      "xver": 0,
      "serverNames": ["${REALITY_SNI}"],
      "privateKey": "${REALITY_PRIV}",
      "shortIds": ["${SHORT_ID}"]
    }
  },
  "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
}
EOF
)"
  xray_put_inbound "$TAG_VISION" "$nb" || return 0
  xray_validate_restart
  open_port "$PORT_VISION" tcp
  grn "VLESS + REALITY + Vision (443) 就绪"
  uri_vision
}

# ----------------------------- 节点：VLESS XHTTP + TLS 过 CDN (2053) -----------------------------
setup_xhttp_cdn(){
  ensure_xray_installed
  ensure_xray_config; ensure_common_creds
  read -rp "Cloudflare 子域名（如 cdn.ahoukuse.me） [${CDN_DOMAIN}]： " _d
  [ -n "${_d:-}" ] && CDN_DOMAIN="$_d"
  [ -n "$CDN_DOMAIN" ] || die "CDN 域名不能为空"
  ylw "该节点需要 Cloudflare 源站证书（后台 SSL/TLS → Origin Server → Create Certificate）。"
  read -rp "源站证书 PEM 文件路径： " cpath
  read -rp "源站私钥 KEY 文件路径： " kpath
  [ -f "$cpath" ] && [ -f "$kpath" ] || die "证书或私钥文件不存在"
  mkdir -p "$XRAY_CERT_DIR"
  install -m644 "$cpath" "${XRAY_CERT_DIR}/${CDN_DOMAIN}.pem"
  install -m600 "$kpath" "${XRAY_CERT_DIR}/${CDN_DOMAIN}.key"
  chown -R nobody:nogroup "$XRAY_CERT_DIR" 2>/dev/null || true

  local nb; nb="$(cat <<EOF
{
  "tag": "${TAG_XHTTP_CDN}",
  "listen": "0.0.0.0",
  "port": ${PORT_XHTTP_CDN},
  "protocol": "vless",
  "settings": {
    "clients": [ { "id": "${UUID}" } ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "xhttp",
    "xhttpSettings": { "host": "${CDN_DOMAIN}", "path": "/xh", "mode": "stream-one" },
    "security": "tls",
    "tlsSettings": {
      "serverName": "${CDN_DOMAIN}",
      "alpn": ["h2","http/1.1"],
      "minVersion": "1.2",
      "certificates": [
        { "certificateFile": "${XRAY_CERT_DIR}/${CDN_DOMAIN}.pem",
          "keyFile": "${XRAY_CERT_DIR}/${CDN_DOMAIN}.key" }
      ]
    }
  },
  "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
}
EOF
)"
  xray_put_inbound "$TAG_XHTTP_CDN" "$nb" || return 0
  xray_validate_restart
  open_port_cf_only "$PORT_XHTTP_CDN"
  save_state
  grn "VLESS + XHTTP + TLS 过 CDN (2053) 就绪"
  ylw "记得在 Cloudflare：加 A 记录 ${CDN_DOMAIN} → ${SERVER_IP}（橙云），SSL 设 Full(strict)，Network 开 gRPC。"
  uri_xhttp_cdn
}

# ----------------------------- 节点：Hysteria2 (UDP 443) -----------------------------
setup_hysteria(){
  ensure_hysteria_installed
  [ -z "$HY_AUTH_PASS" ] && HY_AUTH_PASS="$(openssl rand -base64 16)"
  [ -z "$HY_OBFS_PASS" ] && HY_OBFS_PASS="$(openssl rand -base64 16)"
  read -rp "伪装站点(masquerade) [${HY_MASQ}]： " _m; [ -n "${_m:-}" ] && HY_MASQ="$_m"

  mkdir -p /etc/hysteria
  if [ ! -f "$HY_CERT" ] || [ ! -f "$HY_KEY" ]; then
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$HY_KEY" -out "$HY_CERT" -subj "/CN=${HY_MASQ}" -days 36500
  fi
  chown hysteria:hysteria "$HY_CERT" "$HY_KEY" 2>/dev/null || true
  chmod 600 "$HY_KEY"; chmod 644 "$HY_CERT"

  # 关键：不写 bandwidth（由客户端触发 Brutal）
  cat > "$HY_CONFIG" <<EOF
listen: :${PORT_HY}

tls:
  cert: ${HY_CERT}
  key: ${HY_KEY}

auth:
  type: password
  password: ${HY_AUTH_PASS}

obfs:
  type: salamander
  salamander:
    password: ${HY_OBFS_PASS}

masquerade:
  type: proxy
  proxy:
    url: https://${HY_MASQ}/
    rewriteHost: true
EOF

  systemctl enable --now hysteria-server.service
  systemctl restart hysteria-server.service
  systemctl --no-pager -l status hysteria-server.service | head -n 5 || true
  open_port "$PORT_HY" udp
  save_state
  grn "Hysteria2 (UDP 443, salamander) 就绪"
  uri_hysteria
}

# ----------------------------- 输出客户端 URI（装完即打印）-----------------------------
urlenc_path(){ printf '%%2F%s' "${1#/}"; }  # /xh -> %2Fxh
show_qr(){ command -v qrencode >/dev/null && qrencode -t ANSIUTF8 "$1" || true; }

uri_vision(){
  local u="vless://${UUID}@${SERVER_IP}:${PORT_VISION}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision&type=tcp#reality-vision"
  echo; grn "===== 客户端 URI（VLESS REALITY + Vision，Xray 系客户端）====="
  echo "$u"; show_qr "$u"
}

uri_xhttp_cdn(){
  local u; u="vless://${UUID}@${CDN_DOMAIN}:${PORT_XHTTP_CDN}?encryption=none&security=tls&sni=${CDN_DOMAIN}&fp=chrome&type=xhttp&host=${CDN_DOMAIN}&path=$(urlenc_path /xh)&mode=stream-one#xhttp-cdn"
  echo; grn "===== 客户端 URI（VLESS XHTTP + TLS + CF，Xray 系客户端，连域名）====="
  echo "$u"; show_qr "$u"
}

uri_hysteria(){
  local link="hysteria2://${HY_AUTH_PASS}@${SERVER_IP}:${PORT_HY}?obfs=salamander&obfs-password=${HY_OBFS_PASS}&sni=${HY_MASQ}&insecure=1#hysteria2"
  echo; grn "===== 客户端 URI（Hysteria2，iOS sing-box SFI 原生支持）====="
  echo "$link"; show_qr "$link"
  echo; echo "sing-box outbound（up/down 先填保守值，按实测×0.9 调）："
  cat <<EOF
  {
    "type": "hysteria2",
    "tag": "proxy",
    "server": "${SERVER_IP}",
    "server_port": ${PORT_HY},
    "up_mbps": 20,
    "down_mbps": 50,
    "obfs": { "type": "salamander", "password": "${HY_OBFS_PASS}" },
    "password": "${HY_AUTH_PASS}",
    "tls": { "enabled": true, "server_name": "${HY_MASQ}", "insecure": true }
  }
EOF
}

# ----------------------------- 主菜单 -----------------------------
menu(){
  cat <<'EOF'

============ 节点部署菜单 ============
  1) VLESS REALITY + Vision     (443/tcp,  自动装 Xray)
  2) VLESS XHTTP + TLS + CF      (2053/tcp, 自动装 Xray，需 CF 域名+源站证书)
  3) Hysteria2 (salamander)     (443/udp,  自动装 Hysteria2)
  0) 退出
=====================================
EOF
  read -rp "选择： " c
  case "${c:-}" in
    1) setup_vision ;;
    2) setup_xhttp_cdn ;;
    3) setup_hysteria ;;
    0) exit 0 ;;
    *) red "无效选择" ;;
  esac
}

main(){
  require_root
  install_deps
  load_state
  detect_ip
  save_state
  while true; do menu; echo; read -rp "回车返回菜单…" _; done
}

main "$@"
