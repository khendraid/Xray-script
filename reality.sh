#!/usr/bin/env bash
#
# System Required:  CentOS 7+, Debian9+, Ubuntu16+
# Description:      Script to Xray manage
#
# Copyright (C) 2023 zxcvos
#
# Xray-script: https://github.com/zxcvos/Xray-script
# Xray-core: https://github.com/XTLS/Xray-core
# REALITY: https://github.com/XTLS/REALITY
# Xray-examples: https://github.com/chika0801/Xray-examples
# Docker cloudflare-warp: https://github.com/e7h4n/cloudflare-warp
# Cloudflare Warp: https://github.com/haoel/haoel.github.io#943-docker-%E4%BB%A3%E7%90%86

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin:/snap/bin
export PATH

# color
readonly RED='\033[1;31;31m'
readonly GREEN='\033[1;31;32m'
readonly YELLOW='\033[1;31;33m'
readonly NC='\033[0m'

# config manage
readonly xray_config_manage='/usr/local/etc/xray-script/xray_config_manage.sh'

declare domain
declare domain_path
declare new_port

# status print
function _info() {
  printf "${GREEN}[Info] ${NC}"
  printf -- "%s" "$@"
  printf "\n"
}

function _warn() {
  printf "${YELLOW}[Warning] ${NC}"
  printf -- "%s" "$@"
  printf "\n"
}

function _error() {
  printf "${RED}[Error] ${NC}"
  printf -- "%s" "$@"
  printf "\n"
  exit 1
}

# tools
function _exists() {
  local cmd="$1"
  if eval type type >/dev/null 2>&1; then
    eval type "$cmd" >/dev/null 2>&1
  elif command >/dev/null 2>&1; then
    command -v "$cmd" >/dev/null 2>&1
  else
    which "$cmd" >/dev/null 2>&1
  fi
  local rt=$?
  return ${rt}
}

function _os() {
  local os=""
  [[ -f "/etc/debian_version" ]] && source /etc/os-release && os="${ID}" && printf -- "%s" "${os}" && return
  [[ -f "/etc/redhat-release" ]] && os="centos" && printf -- "%s" "${os}" && return
}

function _os_full() {
  [[ -f /etc/redhat-release ]] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
  [[ -f /etc/os-release ]] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
  [[ -f /etc/lsb-release ]] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

function _os_ver() {
  local main_ver="$(echo $(_os_full) | grep -oE "[0-9.]+")"
  printf -- "%s" "${main_ver%%.*}"
}

function _error_detect() {
  local cmd="$1"
  _info "${cmd}"
  eval ${cmd}
  if [[ $? -ne 0 ]]; then
    _error "Execution command (${cmd}) failed, please check it and try again."
  fi
}

function _is_digit() {
  local input=${1}
  if [[ "$input" =~ ^[0-9]+$ ]]; then
    return 0
  else
    return 1
  fi
}

function _version_ge() {
  test "$(echo "$@" | tr ' ' '\n' | sort -rV | head -n 1)" == "$1"
}

function _is_tlsv1_3_h2() {
  local check_url=$(echo $1 | grep -oE '[^/]+(\.[^/]+)+\b' | head -n 1)
  local check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${check_url}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
  if [[ ${check_num} -eq 3 ]]; then
    return 0
  else
    return 1
  fi
}

function _install() {
  local packages_name="$@"
  case "$(_os)" in
  centos)
    if _exists "dnf"; then
      dnf update -y
      dnf install -y dnf-plugins-core
      dnf update -y
      for package_name in ${packages_name}; do
        dnf install -y ${package_name}
      done
    else
      yum update -y
      yum install -y epel-release yum-utils
      yum update -y
      for package_name in ${packages_name}; do
        yum install -y ${package_name}
      done
    fi
    ;;
  ubuntu | debian)
    apt update -y
    for package_name in ${packages_name}; do
      apt install -y ${package_name}
    done
    ;;
  esac
}

function _systemctl() {
  local cmd="$1"
  local server_name="$2"
  case "${cmd}" in
  start)
    _info "Starting ${server_name} service"
    systemctl -q is-active ${server_name} || systemctl -q start ${server_name}
    systemctl -q is-enabled ${server_name} || systemctl -q enable ${server_name}
    sleep 2
    systemctl -q is-active ${server_name} && _info "${server_name} service started" || _error "${server_name} failed to start"
    ;;
  stop)
    _info "Stopping ${server_name} service"
    systemctl -q is-active ${server_name} && systemctl -q stop ${server_name}
    systemctl -q is-enabled ${server_name} && systemctl -q disable ${server_name}
    sleep 2
    systemctl -q is-active ${server_name} || _info "${server_name} service stopped"
    ;;
  restart)
    _info "Restarting ${server_name} service"
    systemctl -q is-active ${server_name} && systemctl -q restart ${server_name} || systemctl -q start ${server_name}
    systemctl -q is-enabled ${server_name} || systemctl -q enable ${server_name}
    sleep 2
    systemctl -q is-active ${server_name} && _info "${server_name} service restarted" || _error "${server_name} failed to start"
    ;;
  reload)
    _info "Reloading ${server_name} service"
    systemctl -q is-active ${server_name} && systemctl -q reload ${server_name} || systemctl -q start ${server_name}
    systemctl -q is-enabled ${server_name} || systemctl -q enable ${server_name}
    sleep 2
    systemctl -q is-active ${server_name} && _info "${server_name} service reloaded"
    ;;
  dr)
    _info "Reloading systemd configuration files"
    systemctl daemon-reload
    ;;
  esac
}

function _print_list() {
  local p_list=($@)
  for ((i = 1; i <= ${#p_list[@]}; i++)); do
    hint="${p_list[$i - 1]}"
    echo -e "${GREEN}${i}${NC}) ${hint}"
  done
}

function select_data() {
  local data_list=($(awk -v FS=',' '{for (i=1; i<=NF; i++) arr[i]=$i} END{for (i in arr) print arr[i]}' <<<"${1}"))
  local index_list=($(awk -v FS=',' '{for (i=1; i<=NF; i++) arr[i]=$i} END{for (i in arr) print arr[i]}' <<<"${2}"))
  local result_list=()
  if [[ ${#index_list[@]} -ne 0 ]]; then
    for i in "${index_list[@]}"; do
      if _is_digit "${i}" && [ ${i} -ge 1 ] && [ ${i} -le ${#data_list[@]} ]; then
        i=$((i - 1))
        result_list+=("${data_list[${i}]}")
      fi
    done
  else
    result_list=("${data_list[@]}")
  fi
  if [[ ${#result_list[@]} -eq 0 ]]; then
    result_list=("${data_list[@]}")
  fi
  echo "${result_list[@]}"
}

function select_dest() {
  local dest_list=($(jq '.xray.serverNames | keys_unsorted' /usr/local/etc/xray-script/config.json | grep -Eoi '".*"' | sed -En 's|"(.*)"|\1|p'))
  local cur_dest=$(jq -r '.xray.dest' /usr/local/etc/xray-script/config.json)
  local pick_dest=""
  local all_sns=""
  local sns=""
  local prompt="Please select your dest, currently using \"${cur_dest}\" by default, select 0 for custom input: "
  until [[ ${is_dest} =~ ^[Yy]$ ]]; do
    echo -e "---------------- dest List -----------------"
    _print_list "${dest_list[@]}"
    read -p "${prompt}" pick
    if [[ "${pick}" == "" && "${cur_dest}" != "" ]]; then
      pick_dest=${cur_dest}
      break
    fi
    if ! _is_digit "${pick}" || [[ "${pick}" -lt 0 || "${pick}" -gt ${#dest_list[@]} ]]; then
      prompt="Input error, please enter a number between 0-${#dest_list[@]}: "
      continue
    fi
    if [[ "${pick}" == "0" ]]; then
      _warn "If you enter a domain already in the list, it will modify serverNames"
      _warn "When using a custom domain, ensure it's accessible from within China"
      read_domain
      _info "Checking if \"${domain}\" supports TLSv1.3 and h2"
      if ! _is_tlsv1_3_h2 "${domain}"; then
        _warn "\"${domain}\" does not support TLSv1.3 or h2, or Client Hello is not X25519"
        continue
      fi
      _info "\"${domain}\" supports TLSv1.3 and h2"
      _info "Fetching Allowed domains"
      pick_dest=${domain}
      all_sns=$(xray tls ping ${pick_dest} | sed -n '/with SNI/,$p' | sed -En 's/\[(.*)\]/\1/p' | sed -En 's/Allowed domains:\s*//p' | jq -R -c 'split(" ")' | jq --arg sni "${pick_dest}" '. += [$sni]')
      sns=$(echo ${all_sns} | jq 'map(select(test("^[^*]+$"; "g")))' | jq -c 'map(select(test("^((?!cloudflare|akamaized|edgekey|edgesuite|cloudfront|azureedge|msecnd|edgecastcdn|fastly|googleusercontent|kxcdn|maxcdn|stackpathdns|stackpathcdn).)*$"; "ig")))')
      _info "Filtering SNI before wildcard"
      _print_list $(echo ${all_sns} | jq -r '.[]')
      _info "Filtering SNI after wildcard"
      _print_list $(echo ${sns} | jq -r '.[]')
      read -p "Please select the serverName to use, separated by commas, default is all: " pick_num
      sns=$(select_data "$(awk 'BEGIN{ORS=","} {print}' <<<"$(echo ${sns} | jq -r -c '.[]')")" "${pick_num}" | jq -R -c 'split(" ")')
      _info "If there are more serverNames, please edit them manually in /usr/local/etc/xray-script/config.json"
    else
      pick_dest="${dest_list[${pick} - 1]}"
    fi
    read -r -p "Do you want to use dest: \"${pick_dest}\" [y/n] " is_dest
    prompt="Please select your dest, currently using \"${cur_dest}\" by default, select 0 for custom input: "
    echo -e "-------------------------------------------"
  done
  _info "Modifying configuration"
  [[ "${domain_path}" != "" ]] && pick_dest="${pick_dest}${domain_path}"
  if echo ${pick_dest} | grep -q '/$'; then
    pick_dest=$(echo ${pick_dest} | sed -En 's|/+$||p')
  fi
  [[ "${sns}" != "" ]] && jq --argjson sn "{\"${pick_dest}\": ${sns}}" '.xray.serverNames += $sn' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
  jq --arg dest "${pick_dest}" '.xray.dest = $dest' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
}

function read_domain() {
  until [[ ${is_domain} =~ ^[Yy]$ ]]; do
    read -p "Please enter the domain:" domain
    check_domain=$(echo ${domain} | grep -oE '[^/]+(\.[^/]+)+\b' | head -n 1)
    read -r -p "Please confirm domain: \"${check_domain}\" [y/n] " is_domain
  done
  domain_path=$(echo "${domain}" | sed -En "s|.*${check_domain}(/.*)?|\1|p")
  domain=${check_domain}
}

function read_port() {
  local prompt="${1}"
  local cur_port="${2}"
  until [[ ${is_port} =~ ^[Yy]$ ]]; do
    echo "${prompt}"
    read -p "Please enter a custom port (1-65535), default does not modify: " new_port
    if [[ "${new_port}" == "" || ${new_port} -eq ${cur_port} ]]; then
      new_port=${cur_port}
      _info "No change, continuing to use the original port: ${cur_port}"
      break
    fi
    if ! _is_digit "${new_port}" || [[ ${new_port} -lt 1 || ${new_port} -gt 65535 ]]; then
      prompt="Input error, port range is a number between 1-65535"
      continue
    fi
    read -r -p "Please confirm the port: \"${new_port}\" [y/n] " is_port
    prompt="${1}"
  done
}

function read_uuid() {
  _info 'Enter a custom UUID; if it is not in standard format, xray uuid -i "custom string" will be used to map to UUIDv5 for the configuration'
  read -p "Please enter a custom UUID, or leave blank for automatic generation: " in_uuid
}

# check os
function check_os() {
  [[ -z "$(_os)" ]] && _error "Not supported OS"
  case "$(_os)" in
  ubuntu)
    [[ -n "$(_os_ver)" && "$(_os_ver)" -lt 16 ]]  && _error "Not supported OS, please change to Ubuntu 16+ and try again."
    ;;
  debian)
    [[ -n "$(_os_ver)" && "$(_os_ver)" -lt 9 ]] && _error "Not supported OS, please change to Debian 9+ and try again."
    ;;
  centos)
    [[ -n "$(_os_ver)" && "$(_os_ver)" -lt 7 ]] && _error "Not supported OS, please change to CentOS 7+ and try again."
    ;;
  *)
    _error "Not supported OS"
    ;;
  esac
}

function install_dependencies() {
  _info "Downloading related dependencies"
  _install "ca-certificates openssl curl wget jq tzdata"
  case "$(_os)" in
  centos)
    _install "crontabs util-linux iproute procps-ng"
    ;;
  debian | ubuntu)
    _install "cron bsdmainutils iproute2 procps"
    ;;
  esac
}

function install_update_xray() {
  _info "正在安装或更新 Xray"
  _error_detect 'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root --beta'
  jq --arg ver "$(xray version | head -n 1 | cut -d \( -f 1 | grep -Eoi '[0-9.]*')" '.xray.version = $ver' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
  wget -O /usr/local/etc/xray-script/update-dat.sh https://raw.githubusercontent.com/zxcvos/Xray-script/main/tool/update-dat.sh
  chmod a+x /usr/local/etc/xray-script/update-dat.sh
  (crontab -l 2>/dev/null; echo "30 22 * * * /usr/local/etc/xray-script/update-dat.sh >/dev/null 2>&1") | awk '!x[$0]++' | crontab -
  /usr/local/etc/xray-script/update-dat.sh
}

function purge_xray() {
  _info "正在卸载 Xray"
  crontab -l | grep -v "/usr/local/etc/xray-script/update-dat.sh >/dev/null 2>&1" | crontab -
  _systemctl "stop" "xray"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
  rm -rf /etc/systemd/system/xray.service
  rm -rf /etc/systemd/system/xray@.service
  rm -rf /usr/local/bin/xray
  rm -rf /usr/local/etc/xray
  rm -rf /usr/local/share/xray
  rm -rf /var/log/xray
}

function service_xray() {
  _info "正在配置 xray.service"
  wget -O ${HOME}/xray.service https://raw.githubusercontent.com/zxcvos/Xray-script/main/service/xray.service
  mv -f ${HOME}/xray.service /etc/systemd/system/xray.service
  _systemctl dr
}

function config_xray() {
  _info "正在配置 xray config.json"
  "${xray_config_manage}" --path ${HOME}/config.json --download
  local xray_x25519=$(xray x25519)
  local xs_private_key=$(echo ${xray_x25519} | awk '{print $3}')
  local xs_public_key=$(echo ${xray_x25519} | awk '{print $6}')
  # Xray-script config.json
  jq --arg privateKey "${xs_private_key}" '.xray.privateKey = $privateKey' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
  jq --arg publicKey "${xs_public_key}" '.xray.publicKey = $publicKey' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
  # Xray-core config.json
  "${xray_config_manage}" --path ${HOME}/config.json -p ${new_port}
  "${xray_config_manage}" --path ${HOME}/config.json -u ${in_uuid}
  "${xray_config_manage}" --path ${HOME}/config.json -d "$(jq -r '.xray.dest' /usr/local/etc/xray-script/config.json | grep -Eoi '([a-zA-Z0-9](\-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}')"
  "${xray_config_manage}" --path ${HOME}/config.json -sn "$(jq -c -r '.xray | .serverNames[.dest] | .[]' /usr/local/etc/xray-script/config.json | tr '\n' ',')"
  "${xray_config_manage}" --path ${HOME}/config.json -x "${xs_private_key}"
  "${xray_config_manage}" --path ${HOME}/config.json -rsid
  mv -f ${HOME}/config.json /usr/local/etc/xray/config.json
  _systemctl "restart" "xray"
}

function tcp2raw() {
  local current_xray_version=$(xray version | awk '$1=="Xray" {print $2}')
  local tcp2raw_xray_version='24.9.30'
  if _version_ge "${current_xray_version}" "${tcp2raw_xray_version}"; then
    sed -i 's/"network": "tcp"/"network": "raw"/' /usr/local/etc/xray/config.json
    _systemctl "restart" "xray"
  fi
}

function dest2target() {
  local current_xray_version=$(xray version | awk '$1=="Xray" {print $2}')
  local dest2target_xray_version='24.10.31'
  if _version_ge "${current_xray_version}" "${dest2target_xray_version}"; then
    sed -i 's/"dest"/"target"/' /usr/local/etc/xray/config.json
    _systemctl "restart" "xray"
  fi
}

function show_config() {
  local IPv4=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
  local xs_inbound=$(jq '.inbounds[] | select(.tag == "xray-script-xtls-reality")' /usr/local/etc/xray/config.json)
  local xs_port=$(echo ${xs_inbound} | jq '.port')
  local xs_protocol=$(echo ${xs_inbound} | jq '.protocol')
  local xs_ids=$(echo ${xs_inbound} | jq '.settings.clients[] | .id' | tr '\n' ',')
  local xs_public_key=$(jq '.xray.publicKey' /usr/local/etc/xray-script/config.json)
  local xs_serverNames=$(echo ${xs_inbound} | jq '.streamSettings.realitySettings.serverNames[]' | tr '\n' ',')
  local xs_shortIds=$(echo ${xs_inbound} | jq '.streamSettings.realitySettings.shortIds[]' | tr '\n' ',')
  local xs_spiderX=$(jq '.xray.dest' /usr/local/etc/xray-script/config.json)
  [[ "${xs_spiderX}" == "${xs_spiderX##*/}" ]] && xs_spiderX='"/"' || xs_spiderX="\"/${xs_spiderX#*/}"
  echo -e "-------------- client config --------------"
  echo -e "address     : \"${IPv4}\""
  echo -e "port        : ${xs_port}"
  echo -e "protocol    : ${xs_protocol}"
  echo -e "id          : ${xs_ids%,}"
  echo -e "flow        : \"xtls-rprx-vision\""
  echo -e "network     : \"tcp\""
  echo -e "TLS         : \"reality\""
  echo -e "SNI         : ${xs_serverNames%,}"
  echo -e "Fingerprint : \"chrome\""
  echo -e "PublicKey   : ${xs_public_key}"
  echo -e "ShortId     : ${xs_shortIds%,}"
  echo -e "SpiderX     : ${xs_spiderX}"
  echo -e "------------------------------------------"
  read -p "Do you want to generate a share link [y/n]: " is_show_share_link
  echo
  if [[ ${is_show_share_link} =~ ^[Yy]$ ]]; then
    show_share_link
  else
    echo -e "------------------------------------------"
    echo -e "${RED}This script is for educational and learning purposes only, please do not use it for illegal activities.${NC}"
    echo -e "${RED}The internet is not above the law; engaging in illegal activities will result in legal consequences.${NC}"
    echo -e "------------------------------------------"
  fi
}

function show_share_link() {
  local sl=""
  # share lnk contents
  local sl_host=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
  local sl_inbound=$(jq '.inbounds[] | select(.tag == "xray-script-xtls-reality")' /usr/local/etc/xray/config.json)
  local sl_port=$(echo ${sl_inbound} | jq -r '.port')
  local sl_protocol=$(echo ${sl_inbound} | jq -r '.protocol')
  local sl_ids=$(echo ${sl_inbound} | jq -r '.settings.clients[] | .id')
  local sl_public_key=$(jq -r '.xray.publicKey' /usr/local/etc/xray-script/config.json)
  local sl_serverNames=$(echo ${sl_inbound} | jq -r '.streamSettings.realitySettings.serverNames[]')
  local sl_shortIds=$(echo ${sl_inbound} | jq '.streamSettings.realitySettings.shortIds[]')
  # share link fields
  local sl_uuid=""
  local sl_security='security=reality'
  local sl_flow='flow=xtls-rprx-vision'
  local sl_fingerprint='fp=chrome'
  local sl_publicKey="pbk=${sl_public_key}"
  local sl_sni=""
  local sl_shortId=""
  local sl_spiderX='spx=%2F'
  local sl_descriptive_text='VLESS-XTLS-uTLS-REALITY'
  # select show
 _print_list "${sl_ids[@]}"
read -p "Please select the UUID for generating share links, separated by commas, default is all: " pick_num
sl_id=($(select_data "$(awk 'BEGIN{ORS=","} {print}' <<<"${sl_ids[@]}")" "${pick_num}"))
_print_list "${sl_serverNames[@]}"
read -p "Please select the serverName for generating share links, separated by commas, default is all: " pick_num
sl_serverNames=($(select_data "$(awk 'BEGIN{ORS=","} {print}' <<<"${sl_serverNames[@]}")" "${pick_num}"))
_print_list "${sl_shortIds[@]}"
read -p "Please select the shortId for generating share links, separated by commas, default is all: " pick_num
sl_shortIds=($(select_data "$(awk 'BEGIN{ORS=","} {print}' <<<"${sl_shortIds[@]}")" "${pick_num}"))
echo -e "--------------- share link ---------------"
for sl_id in "${sl_ids[@]}"; do
  sl_uuid="${sl_id}"
  for sl_serverName in "${sl_serverNames[@]}"; do
    sl_sni="sni=${sl_serverName}"
    echo -e "---------- serverName ${sl_sni} ----------"
    for sl_shortId in "${sl_shortIds[@]}"; do
      [[ "${sl_shortId//\"/}" != "" ]] && sl_shortId="sid=${sl_shortId//\"/}" || sl_shortId=""
      sl="${sl_protocol}://${sl_uuid}@${sl_host}:${sl_port}?${sl_security}&${sl_flow}&${sl_fingerprint}&${sl_publicKey}&${sl_sni}&${sl_spiderX}&${sl_shortId}"
      echo "${sl%&}#${sl_descriptive_text}"
    done
    echo -e "------------------------------------------------"
  done
done
echo -e "------------------------------------------"
echo -e "${RED}This script is for educational and learning purposes only, please do not use it for illegal activities.${NC}"
echo -e "${RED}The internet is not above the law; engaging in illegal activities will result in legal consequences.${NC}"
echo -e "------------------------------------------"
}

function menu() {
  check_os
  clear
  echo -e "--------------- Xray-script ---------------"
  echo -e " Version      : ${GREEN}v2023-03-15${NC}(${RED}beta${NC})"
  echo -e " Description  : Xray Management Script"
  echo -e "----------------- Installation Management ----------------"
  echo -e "${GREEN}1.${NC} Install"
  echo -e "${GREEN}2.${NC} Update"
  echo -e "${GREEN}3.${NC} Uninstall"
  echo -e "----------------- Operation Management ----------------"
  echo -e "${GREEN}4.${NC} Start"
  echo -e "${GREEN}5.${NC} Stop"
  echo -e "${GREEN}6.${NC} Restart"
  echo -e "----------------- Configuration Management ----------------"
  echo -e "${GREEN}101.${NC} View Configuration"
  echo -e "${GREEN}102.${NC} Statistics Information"
  echo -e "${GREEN}103.${NC} Modify ID"
  echo -e "${GREEN}104.${NC} Modify Dest"
  echo -e "${GREEN}105.${NC} Modify x25519 Key"
  echo -e "${GREEN}106.${NC} Modify shortIds"
  echo -e "${GREEN}107.${NC} Modify xray Listening Port"
  echo -e "${GREEN}108.${NC} Refresh Existing shortIds"
  echo -e "${GREEN}109.${NC} Append Custom shortIds"
  echo -e "${GREEN}110.${NC} Use WARP for Traffic Routing, Enable OpenAI"
  echo -e "----------------- Other Options ----------------"
  echo -e "${GREEN}201.${NC} Update to the Latest Stable Kernel"
  echo -e "${GREEN}202.${NC} Uninstall Unnecessary Kernels"
  echo -e "${GREEN}203.${NC} Modify SSH Port"
  echo -e "${GREEN}204.${NC} Network Connection Optimization"
  echo -e "-------------------------------------------"
  echo -e "${RED}0.${NC} Exit"
  read -rp "Choose: " idx
  ! _is_digit "${idx}" && _error "Please enter a correct option value"
  if [[ ! -d /usr/local/etc/xray-script && (${idx} -ne 0 && ${idx} -ne 1 && ${idx} -lt 201) ]]; then
    _error "Xray-script not used for installation"
  fi
  if [ -d /usr/local/etc/xray-script ] && ([ ${idx} -gt 102 ] || [ ${idx} -lt 111 ]); then
    wget -qO ${xray_config_manage} https://raw.githubusercontent.com/zxcvos/Xray-script/main/tool/xray_config_manage.sh
    chmod a+x ${xray_config_manage}
  fi
  case "${idx}" in
  1)
    if [[ ! -d /usr/local/etc/xray-script ]]; then
      mkdir -p /usr/local/etc/xray-script
      wget -O /usr/local/etc/xray-script/config.json https://raw.githubusercontent.com/zxcvos/Xray-script/main/config/config.json
      wget -O ${xray_config_manage} https://raw.githubusercontent.com/zxcvos/Xray-script/main/tool/xray_config_manage.sh
      chmod a+x ${xray_config_manage}
      install_dependencies
      install_update_xray
      local xs_port=$(jq '.xray.port' /usr/local/etc/xray-script/config.json)
      read_port "xray config set to use by default: ${xs_port}" "${xs_port}"
      read_uuid
      select_dest
      config_xray
      tcp2raw
      dest2target
      show_config
    fi
    ;;
  2)
    _info "Checking if there's a new version of Xray"
    local current_xray_version="$(jq -r '.xray.version' /usr/local/etc/xray-script/config.json)"
    local latest_xray_version="$(wget -qO- --no-check-certificate https://api.github.com/repos/XTLS/Xray-core/releases | jq -r '.[0].tag_name ' | cut -d v -f 2)"
    if _version_ge "${latest_xray_version}" "${current_xray_version}"; then
      _info "A new version is available"
      install_update_xray
      tcp2raw
      dest2target
    else
      _info "You are currently using the latest version: ${current_xray_version}"
    fi
    ;;
  3)
    purge_xray
    [[ -f /usr/local/etc/xray-script/sysctl.conf.bak ]] && mv -f /usr/local/etc/xray-script/sysctl.conf.bak /etc/sysctl.conf && _info "Network connection settings have been restored"
    rm -rf /usr/local/etc/xray-script
    if docker ps | grep -q cloudflare-warp; then
      _info 'Stopping cloudflare-warp'
      docker container stop cloudflare-warp
      docker container rm cloudflare-warp
    fi
    if docker images | grep -q e7h4n/cloudflare-warp; then
      _info 'Uninstalling cloudflare-warp'
      docker image rm e7h4n/cloudflare-warp
    fi
    rm -rf ${HOME}/.warp
    _info 'Please uninstall Docker manually'
    _info "Uninstallation completed"
    ;;
  4)
    _systemctl "start" "xray"
    ;;
  5)
    _systemctl "stop" "xray"
    ;;
  6)
    _systemctl "restart" "xray"
    ;;
  101)
    show_config
    ;;
  102)
    [[ -f /usr/local/etc/xray-script/traffic.sh ]] || wget -O /usr/local/etc/xray-script/traffic.sh https://raw.githubusercontent.com/zxcvos/Xray-script/main/tool/traffic.sh
    bash /usr/local/etc/xray-script/traffic.sh
    ;;
  103)
    read_uuid
    _info "Modifying user ID"
    "${xray_config_manage}" -u ${in_uuid}
    _info "Successfully modified user ID"
    _systemctl "restart" "xray"
    show_config
    ;;
  104)
    _info "Modifying dest(target) and serverNames"
    select_dest
    local current_xray_version=$(xray version | awk '$1=="Xray" {print $2}')
    local dest2target_xray_version='24.10.31'
    if _version_ge "${current_xray_version}" "${dest2target_xray_version}"; then
      "${xray_config_manage}" -d "$(jq -r '.xray.target' /usr/local/etc/xray-script/config.json | grep -Eoi '([a-zA-Z0-9](\-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}')"
      "${xray_config_manage}" -sn "$(jq -c -r '.xray | .serverNames[.target] | .[]' /usr/local/etc/xray-script/config.json | tr '\n' ',')"
    else
      "${xray_config_manage}" -d "$(jq -r '.xray.dest' /usr/local/etc/xray-script/config.json | grep -Eoi '([a-zA-Z0-9](\-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}')"
      "${xray_config_manage}" -sn "$(jq -c -r '.xray | .serverNames[.dest] | .[]' /usr/local/etc/xray-script/config.json | tr '\n' ',')"
    fi
    _info "Successfully modified dest(target) and serverNames"
    _systemctl "restart" "xray"
    show_config
    ;;
  105)
    _info "Modifying x25519 key"
    local xray_x25519=$(xray x25519)
    local xs_private_key=$(echo ${xray_x25519} | awk '{print $3}')
    local xs_public_key=$(echo ${xray_x25519} | awk '{print $6}')
    # Xray-script config.json
    jq --arg privateKey "${xs_private_key}" '.xray.privateKey = $privateKey' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
    jq --arg publicKey "${xs_public_key}" '.xray.publicKey = $publicKey' /usr/local/etc/xray-script/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray-script/config.json
    # Xray-core config.json
    "${xray_config_manage}" -x "${xs_private_key}"
    _info "Successfully modified x25519 key"
    _systemctl "restart" "xray"
    show_config
    ;;
  106)
    _info "Definition of shortId value: accepts a hexadecimal number, must be an even length, maximum length is 16"
    _info "The default value for the shortId list is [\"\"] which allows the client's shortId to be empty if this is set"
    read -p "Please enter custom shortIds, separate multiple values with commas: " sid_str
    _info "Modifying shortIds"
    "${xray_config_manage}" -sid "${sid_str}"
    _info "Successfully modified shortIds"
    _systemctl "restart" "xray"
    show_config
    ;;
  107)
    local xs_port=$(jq '.inbounds[] | select(.tag == "xray-script-xtls-reality") | .port' /usr/local/etc/xray/config.json)
    read_port "Current xray listening port is: ${xs_port}" "${xs_port}"
    if [[ "${new_port}" && ${new_port} -ne ${xs_port} ]]; then
      "${xray_config_manage}" -p ${new_port}
      _info "Current xray listening port has been changed to: ${new_port}"
      _systemctl "restart" "xray"
      show_config
    fi
    ;;
  108)
    _info "Modifying shortIds"
    "${xray_config_manage}" -rsid
    _info "Successfully modified shortIds"
    _systemctl "restart" "xray"
    show_config
    ;;
  109)
    until [ ${#sid_str} -gt 0 ] && [ ${#sid_str} -le 16 ] && [ $((${#sid_str} % 2)) -eq 0 ]; do
      _info "Definition of shortId value: accepts a hexadecimal number, must be an even length, maximum length is 16"
      read -p "Please enter custom shortIds, cannot be empty, separate multiple values with commas: " sid_str
    done
    _info "Adding custom shortIds"
    "${xray_config_manage}" -asid "${sid_str}"
    _info "Successfully added custom shortIds"
    _systemctl "restart" "xray"
    show_config
    ;;
  110)
if ! _exists "docker"; then
  read -r -p "The script uses Docker for WARP management. Do you want to install Docker [y/n] " is_docker
  if [[ ${is_docker} =~ ^[Yy]$ ]]; then
    curl -fsSL -o /usr/local/etc/xray-script/install-docker.sh https://get.docker.com
    if [[ "$(_os)" == "centos" && "$(_os_ver)" -eq 8 ]]; then
      sed -i 's|$sh_c "$pkg_manager install -y -q $pkgs"| $sh_c "$pkg_manager install -y -q $pkgs --allowerasing"|' /usr/local/etc/xray-script/install-docker.sh
    fi
    sh /usr/local/etc/xray-script/install-docker.sh --dry-run
    sh /usr/local/etc/xray-script/install-docker.sh
  else
    _warn "Canceling traffic routing operation"
    exit 0
  fi
fi
if docker ps | grep -q cloudflare-warp; then
  _info "WARP has been enabled, please do not set it up again"
else
  _info "Fetching and starting the cloudflare-warp image"
  docker run -v $HOME/.warp:/var/lib/cloudflare-warp:rw --restart=always --name=cloudflare-warp e7h4n/cloudflare-warp
  _info "Configuring routing"
  local routing='{"type":"field","domain":["domain:ipinfo.io","domain:ip.sb","geosite:openai"],"outboundTag":"warp"}'
  _info "Configuring outbounds"
  local outbound=$(echo '{"tag":"warp","protocol":"socks","settings":{"servers":[{"address":"172.17.0.2","port":40001}]}}' | jq -c --arg addr "$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cloudflare-warp)" '.settings.servers[].address = $addr')
  jq --argjson routing "${routing}" '.routing.rules += [$routing]' /usr/local/etc/xray/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray/config.json
  jq --argjson outbound "${outbound}" '.outbounds += [$outbound]' /usr/local/etc/xray/config.json >/usr/local/etc/xray-script/new.json && mv -f /usr/local/etc/xray-script/new.json /usr/local/etc/xray/config.json
  _systemctl "restart" "xray"
  show_config
fi
;;
201)
  bash <(wget -qO- https://raw.githubusercontent.com/zxcvos/system-automation-scripts/main/update-kernel.sh)
    ;;
  202)
    bash <(wget -qO- https://raw.githubusercontent.com/zxcvos/system-automation-scripts/main/remove-kernel.sh)
    ;;
  203)
    local ssh_port=$(sed -En "s/^[#pP].*ort\s*([0-9]*)$/\1/p" /etc/ssh/sshd_config)
    read_port "Current SSH connection port is: ${ssh_port}" "${ssh_port}"
    if [[ "${new_port}" && ${new_port} -ne ${ssh_port} ]]; then
      sed -i "s/^[#pP].*ort\s*[0-9]*$/Port ${new_port}/" /etc/ssh/sshd_config
      systemctl restart sshd
      _info "Current SSH connection port has been changed to: ${new_port}"
    fi
    ;;
  204)
    read -r -p "Choose network connection optimization? [y/n] " is_opt
    if [[ ${is_opt} =~ ^[Yy]$ ]]; then
      [[ -f /usr/local/etc/xray-script/sysctl.conf.bak ]] || cp -af /etc/sysctl.conf /usr/local/etc/xray-script/sysctl.conf.bak
      wget -O /etc/sysctl.conf https://raw.githubusercontent.com/zxcvos/Xray-script/main/config/sysctl.conf
      sysctl -p
    fi
    ;;
  0)
    exit 0
    ;;
  *)
    _error "Please enter a correct option value"
    ;;
  esac
}

[[ $EUID -ne 0 ]] && _error "This script must be run as root"

menu
