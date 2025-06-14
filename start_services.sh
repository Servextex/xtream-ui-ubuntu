#! /bin/bash
kill $(ps aux | grep 'xtreamcodes' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
sleep 1
kill $(ps aux | grep 'xtreamcodes' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
sleep 1
kill $(ps aux | grep 'xtreamcodes' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
sleep 4
sudo rm /home/xtreamcodes/iptv_xtream_codes/adtools/balancer/*.json 2>/dev/null &
echo "" > /home/xtreamcodes/iptv_xtream_codes/logs/error.log 2>/dev/null &
echo "" > /home/xtreamcodes/iptv_xtream_codes/logs/rtmp_error.log 2>/dev/null &
echo "" > /home/xtreamcodes/iptv_xtream_codes/logs/access.log 2>/dev/null &
sleep 1
sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/crons/setup_cache.php 2>/dev/null
sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/tools/signal_receiver.php >/dev/null 2>/dev/null &
sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/tools/pipe_reader.php >/dev/null 2>/dev/null &
chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb 2>/dev/null
wget -qO /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb https://github.com/Servextex/xtream-ui-ubuntu/releases/download/start/GeoLite2.mmdb 2>/dev/null
wget -qO /home/xtreamcodes/iptv_xtream_codes/diagnosticar.py https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/main/diagnosticar.py 2>/dev/null
wget -qO /home/xtreamcodes/iptv_xtream_codes/verificar.py https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/main/verificar.py 2>/dev/null
chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb 2>/dev/null
geoliteversion=$(wget -qO- https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/refs/heads/main/Geolite2_status.json | jq -r ".version")
PASSMYSQL=$(python3 /home/xtreamcodes/iptv_xtream_codes/pytools/config.py DECRYPT | grep Password | sed "s|Password:            ||g")
mysql -u user_iptvpro -p$PASSMYSQL -P 7999 xtream_iptvpro -e "UPDATE admin_settings SET value = '$geoliteversion' WHERE admin_settings.type = 'geolite2_version'; " 2>/dev/null
chown -R xtreamcodes:xtreamcodes /sys/class/net 2>/dev/null
chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null
sleep 4
/home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp
/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx
daemonize -p /home/xtreamcodes/iptv_xtream_codes/php/VaiIb8.pid /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/VaiIb8.conf
daemonize -p /home/xtreamcodes/iptv_xtream_codes/php/JdlJXm.pid /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/JdlJXm.conf
daemonize -p /home/xtreamcodes/iptv_xtream_codes/php/CWcfSP.pid /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/CWcfSP.conf
