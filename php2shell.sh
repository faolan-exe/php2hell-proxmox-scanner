#!/bin/bash
UPGRADE=0
LOCAL=0
SINCE=2026-10-20
for a in "$@"; do
  case "$a" in
    --upgrade) UPGRADE=1 ;;
    --local) LOCAL=1 ;;
    --since=*) SINCE=${a#--since=} ;;
    -h|--help)
      echo "Usage: $0 [--upgrade] [--local] [--since=YYYY-MM-DD]"
      echo "  (no flags)  check only, on a Proxmox node all running LXCs"
      echo "  --upgrade   upgrade apt-installed PHP and restart apache2/php-fpm"
      echo "  --local     only check this host, do not iterate LXCs"
      echo "  --since     reference date for the heuristics (default $SINCE)"
      exit 0 ;;
    *) echo "Unknown option: $a (see --help)"; exit 1 ;;
  esac
done

fixed_for() {
  case "$1" in
    8.2) echo 8.2.35 ;;
    8.3) echo 8.3.36 ;;
    8.4) echo 8.4.27 ;;
    8.5) echo 8.5.12 ;;
    *) echo EOL ;;
  esac
}

rate() {
  local label="$1" ver="$2" changelog="$3" br up fx
  br=$(grep -oE '^[0-9]+\.[0-9]+' <<<"$ver")
  up=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$ver")
  fx=$(fixed_for "$br")
  if [ -n "$changelog" ] && [ -f "$changelog" ] && zgrep -qE 'CVE-2026-10961[89]' "$changelog"; then
    echo "  PATCHED (backport)   $label  $ver"
  elif [ "$fx" = EOL ]; then
    echo "  EOL, NO FIX          $label  $ver"
  elif [ "$(printf '%s\n' "$fx" "$up" | sort -V | head -1)" = "$fx" ]; then
    echo "  PATCHED              $label  $ver"
  else
    echo "  NOT PATCHED          $label  $ver  (needs >= $fx)"
  fi
}

installed() {
  dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' "$@" 2>/dev/null | awk '$1=="ii"{print $2}'
}

show() {
  local title="$1" data="$2" n
  [ -z "$data" ] && return
  HITS=$((HITS + 1))
  n=$(wc -l <<<"$data")
  echo "  REVIEW: $title ($n)"
  head -15 <<<"$data" | sed 's/^/      /'
  [ "$n" -gt 15 ] && echo "      ..."
}

webroots() {
  {
    [ -d /var/www ] && echo /var/www
    grep -rhoiE '^\s*DocumentRoot\s+"?[^" ]+' /etc/apache2/sites-enabled /etc/httpd/conf.d 2>/dev/null | awk '{print $2}' | tr -d '"'
    grep -rhoE '^\s*root\s+[^;]+' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | awk '{print $2}'
    [ -d /var/lib/docker/volumes ] && echo /var/lib/docker/volumes
  } | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done
}

hunt() {
  local roots c u
  HITS=0
  echo "  -- heuristics since $SINCE"
  roots=$(webroots)
  if [ -n "$roots" ]; then
    show "new or modified PHP/.htaccess/.user.ini files" "$(find $roots \( -name data -o -name nextcloud_aio_nextcloud_data -o -name node_modules \) -prune -o -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.user.ini' -o -name '.htaccess' \) \( -newermt "$SINCE" -o -newerct "$SINCE" \) -print 2>/dev/null | sort -u)"
    show "webshell patterns in code" "$(grep -rlE --include='*.php' --include='*.phtml' --exclude-dir=data --exclude-dir=nextcloud_aio_nextcloud_data --exclude-dir=node_modules '(eval|assert|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|gzuncompress|str_rot13)' $roots 2>/dev/null | sort -u)"
  fi
  show "executables or PHP files in tmp" "$(find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -u+x -o -name '*.php' \) \( -newermt "$SINCE" -o -newerct "$SINCE" \) 2>/dev/null)"
  show "shell/network tools running as web user" "$(ps -eo uid=,pid=,comm=,args= 2>/dev/null | awk '($1==33||$1==82||$1==48) && $3 ~ /^(sh|bash|dash|ash|nc|ncat|netcat|socat|curl|wget|perl|python[0-9.]*|ruby|xmrig|kinsing|kdevtmpfsi|busybox)$/ && $0 !~ /nc -lk 9001$/')"
  if command -v ss >/dev/null; then
    show "outbound internet connections of web user" "$(ss -Htnpe state established 2>/dev/null | awk '/uid:(33|82|48) /{n=split($3,a,":"); if (a[n]>=32768) print $4, $NF}' | grep -vE '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[::1\]|\[f[cde]|\[::ffff:(10|127|192\.168)\.)')"
  fi
  for u in www-data apache nginx http; do
    show "crontab of $u" "$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')"
  done
  if command -v docker >/dev/null; then
    for c in $(docker ps --format '{{.Names}}'); do
      show "docker diff $c" "$(docker diff "$c" 2>/dev/null | awk '$1!="D"' | grep -E '\.(php|phtml|phar)$')"
    done
  fi
  [ "$HITS" = 0 ] && echo "  nothing suspicious"
}

run_local() {
  echo "== $(hostname)"
  local found=0 branches br pkgs c v f p
  if command -v dpkg-query >/dev/null; then
    branches=$(installed 'php*-common' | grep -oE '^php[0-9]+\.[0-9]+-common$' | sed -E 's/^php|-common$//g')
    if [ "$UPGRADE" = 1 ] && [ -n "$branches" ]; then
      apt-get update -qq
      for br in $branches; do
        pkgs=$(installed "php$br*" "libapache2-mod-php$br")
        [ -n "$pkgs" ] && apt-get -o Acquire::Retries=20 install -y -qq --only-upgrade $pkgs >/dev/null
        for s in apache2 "php$br-fpm"; do
          systemctl is-active -q "$s" && systemctl restart "$s"
        done
      done
    fi
    for br in $branches; do
      found=1
      rate "apt:php$br" "$(dpkg-query -W -f='${Version}' "php$br-common")" "/usr/share/doc/php$br-common/changelog.Debian.gz"
    done
  fi
  if command -v docker >/dev/null; then
    for c in $(docker ps --format '{{.Names}}'); do
      v=$(docker exec "$c" sh -c 'command -v php >/dev/null 2>&1 && php -r "echo PHP_VERSION;"' 2>/dev/null)
      if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        found=1
        rate "docker:$c" "$v"
      fi
    done
  fi
  [ "$found" = 0 ] && echo "  no PHP found"
  for f in $(grep -lE '(libphp[^/ ]*|php-fpm[^/ ]*|bin/php[^/ ]*|/lib/php/[^ ]*) \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null); do
    p=${f//[^0-9]/}
    echo "  OLD PHP STILL IN MEMORY: PID $p ($(ps -p "$p" -o comm= 2>/dev/null)), restart that service"
  done
  [ "$found" = 1 ] && hunt
}

if [ "$LOCAL" = 0 ] && command -v pct >/dev/null; then
  self=$(readlink -f "$0")
  args=(--local "--since=$SINCE")
  [ "$UPGRADE" = 1 ] && args+=(--upgrade)
  for id in $(pct list | awk 'NR>1 && $2=="running"{print $1}'); do
    if ! pct exec "$id" -- test -x /bin/bash; then
      echo "== CT $id: no bash, skipped"
      continue
    fi
    pct push "$id" "$self" /tmp/php2shell.sh
    pct exec "$id" -- bash /tmp/php2shell.sh "${args[@]}"
    pct exec "$id" -- rm -f /tmp/php2shell.sh
  done
else
  run_local
fi
