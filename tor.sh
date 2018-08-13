#!/bin/bash

sudo apt -qqy install curl
clear

TARBALLURL=`curl -Ls https://api.github.com/repos/VulcanoCrypto/Vulcano/releases/latest | grep browser_download_url | grep linux64 | cut -d '"' -f 4`
TARBALLNAME=`curl -Ls https://api.github.com/repos/VulcanoCrypto/Vulcano/releases/latest | grep browser_download_url | grep linux64 | cut -d '"' -f 4 | cut -d '/' -f 9`

if [ "$(id -u)" != "0" ]; then
    echo "Sorry, this script needs to be run as root. Do \"sudo bash run.sh\""
    exit 1
fi

sudo echo "Preparing installation..."
if ifconfig | grep wlan0 | grep RUNNING; then
  PSK=`sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep -o -o 'psk=".*"' | cut -c 5- | sed 's/"//g'`
  SSID=`sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep -o -o 'ssid=".*"' | cut -c 6- | sed 's/"//g'`
  NEWPSK=`wpa_passphrase $SSID $PSK | head -4 | tail -1 | cut -c 6-`
  sudo sed -i s/psk=.*$/psk=$NEWPSK/g /etc/wpa_supplicant/wpa_supplicant.conf
fi
sudo apt-get -y update
sleep 2
sudo apt-get -y upgrade
sleep 2
sudo apt-get -y dist-upgrade
sleep 2
sudo apt-get update -y
sleep 2
sudo apt-get install htop -y
sleep 3
sudo apt-get install nano -y
sleep 3
sudo apt-get install ufw -y
sleep 3
sudo apt-get install fail2ban -y
sleep 3
sudo apt-get install tor -y
sleep 3
sudo apt-get install git -y
sleep 3
sudo apt install golang -y
sleep 3
sudo wget --directory-prefix=/etc/fail2ban/ https://raw.githubusercontent.com/vulcanocrypto/shn/master/jail.local
sudo apt install unattended-upgrades -y
sleep 3
sudo sh -c 'echo "Unattended-Upgrade::Allowed-Origins {" >> /etc/apt/apt.conf.d/50unattended-upgrades'
sudo sh -c 'echo "        "${distro_id}:${distro_codename}";" >> /etc/apt/apt.conf.d/50unattended-upgrades'
sudo sh -c 'echo "        "${distro_id}:${distro_codename}-security";" >> /etc/apt/apt.conf.d/50unattended-upgrades'
sudo sh -c 'echo "APT::Periodic::AutocleanInterval "7";" >> /etc/apt/apt.conf.d/20auto-upgrades'
sudo sh -c 'echo "APT::Periodic::Unattended-Upgrade "1";" >> /etc/apt/apt.conf.d/20auto-upgrades'
sudo adduser --gecos "" vulcano --disabled-password > /dev/null
sleep 1
sudo cat > /etc/systemd/system/vulcanod.service << EOL
[Unit]
Description=Vulcanos's distributed currency daemon
After=network.target
[Service]
User=vulcano
Group=vulcano
WorkingDirectory=/home/vulcano
Type=forking
ExecStart=/usr/bin/vulcanod -datadir=/home/vulcano/.vulcanocore -conf=/home/vulcano/.vulcanocore/vulcano.conf -daemon
ExecStop=/usr/bin/vulcano-cli -datadir=/home/vulcano/.vulcanocore -conf=/home/vulcano/.vulcanocore/vulcano.conf stop
#KillMode=process
Restart=always
TimeoutSec=120
RestartSec=30
[Install]
WantedBy=multi-user.target
EOL
sleep 1
#Golang Installation
sudo wget https://storage.googleapis.com/golang/go1.9.linux-armv6l.tar.gz
sudo tar -C /usr/local -xzf go1.9.linux-armv6l.tar.gz
sudo rm go1.9.linux-armv6l.tar.gz
sudo mkdir -p /home/vulcano/go/bin
sleep 1
# put into global /etc/profile
export PATH=$PATH:/usr/local/go/bin
sleep 1
# put into user's ~/.profile
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
source /etc/profile
source ~/.profile
sleep 1

sudo mkdir /home/vulcano/.vulcanocore
sudo touch /home/vulcano/.vulcanocore/vulcano.conf
sudo chown -R vulcano:vulcano /home/vulcano/.vulcanocore
RPCUSER=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
RPCPASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

sudo cat > /home/vulcano/.vulcanocore/vulcano.conf << EOL
rpcusername=${RPCUSER}
rpcpassword=${RPCPASSWORD}
daemon=1
EOL

sudo ufw allow 9050
sleep 2
sudo ufw allow 62543
sleep 2
sudo ufw allow from 127.0.0.1 to 127.0.0.1 port 62541
sleep 2
sudo ufw allow 22
yes | sudo ufw enable
sleep 2
sudo wget $TARBALLURL
sleep 2
sudo tar -xzf $TARBALLNAME
sudo mv bin vulcano
cd vulcano
sudo cp vulcano* /usr/bin
sudo sh -c 'echo "#" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "### TOR CONFIG ###" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "onion=127.0.0.1:9050" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "onlynet=tor" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "bind=127.0.0.1" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "listen=1" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "dnsseed=0" >> /home/vulcano/.vulcanocore/vulcano.conf'
sudo sh -c 'echo "### XERONET ROCKET TORRC for BWK ###" >> /etc/tor/torrc'
sudo sh -c 'echo "HiddenServiceDir /var/lib/tor/hidden_service/" >> /etc/tor/torrc'
sudo sh -c 'echo "ClientOnly 1" >> /etc/tor/torrc'
sudo sh -c 'echo "ControlPort 9051" >> /etc/tor/torrc'
sudo sh -c 'echo "NumEntryGuards 4" >> /etc/tor/torrc'
sudo sh -c 'echo "NumDirectoryGuards 3" >> /etc/tor/torrc'
sudo sh -c 'echo "GuardLifetime 2764800" >> /etc/tor/torrc'
sudo sh -c 'echo "GeoIPExcludeUnknown 1" >> /etc/tor/torrc'
sudo sh -c 'echo "EntryNodes  31.185.104.19/32,31.185.104.20/31,46.182.106.190/32,51.15.13.245/32,51.15.43.232/32,51.15.44.197/32,51.15.45.97/32,51.15.46.49/32,51.15.50.133/32,51.15.57.177/32,51.15.57.79/32,51.15.60.255/32,51.15.60.62/32,62.102.148.67/32,62.138.7.171/32,77.109.139.87/32,78.142.140.242/32,80.67.172.162/32,81.7.10.29/32,82.94.251.227/32,85.248.227.163/32,85.248.227.164/31,86.59.119.83/32,86.59.119.88/32,89.234.157.254/32,91.121.23.100/32,94.140.120.44/32,94.242.246.23/32,94.242.246.24/32,94.252.114.48/32,95.142.161.63/32,134.119.3.164/32,171.25.193.20/32,171.25.193.25/32,171.25.193.77/32,171.25.193.78/32,176.10.104.240/32,176.10.104.243/32,176.126.252.11/32,176.126.252.12/32,178.16.208.55/32,178.16.208.56/30,178.16.208.60/31,178.16.208.62/32,178.20.55.16/32,178.20.55.18/32,178.209.42.84/32,185.100.84.82/32,185.100.86.100/32,185.34.33.2/32,185.86.149.75/32,188.118.198.244/32,192.36.27.4/32,192.36.27.6/31,192.42.116.16/32,212.51.156.78/32" >> /etc/tor/torrc'
sudo sh -c 'echo "ExitNodes  31.185.104.19/32,31.185.104.20/31,46.182.106.190/32,51.15.43.232/32,51.15.44.197/32,51.15.45.97/32,51.15.46.49/32,51.15.50.133/32,51.15.57.177/32,51.15.57.79/32,51.15.60.255/32,51.15.60.62/32,62.102.148.67/32,77.109.139.87/32,80.67.172.162/32,85.248.227.163/32,85.248.227.164/31,89.234.157.254/32,94.242.246.23/32,94.242.246.24/32,95.142.161.63/32,171.25.193.20/32,171.25.193.25/32,171.25.193.77/32,171.25.193.78/32,176.10.104.240/32,176.10.104.243/32,176.126.252.11/32,176.126.252.12/32,178.20.55.16/32,178.20.55.18/32,178.209.42.84/32,185.100.84.82/32,185.100.86.100/32,185.34.33.2/32,192.36.27.4/32,192.36.27.6/31,192.42.116.16/32,212.16.104.33/32" >> /etc/tor/torrc'
sudo sh -c 'echo "ExcludeNodes  default,Unnamed,{ae},{af},{ag},{ao},{az},{ba},{bb},{bd},{bh},{bi},{bn},{bt},{bw},{by},{cd},{cf},{cg},{ci},{ck},{cm},{cn},{cu},{cy},{dj},{dm},{dz},{eg},{er},{et},{fj},{ga},{gd},{gh},{gm},{gn},{gq},{gy},{hr},{ht},{id},{in},{iq},{ir},{jm},{jo},{ke},{kg},{kh},{ki},{km},{kn},{kp},{kw},{kz},{la},{lb},{lc},{lk},{lr},{ly},{ma},{me},{mk},{ml},{mm},{mr},{mu},{mv},{mw},{my},{na},{ng},{om},{pg},{ph},{pk},{ps},{qa},{rs},{ru},{rw},{sa},{sb},{sd},{sg},{si},{sl},{sn},{so},{st},{sy},{sz},{td},{tg},{th},{tj},{tm},{tn},{to},{tr},{tt},{tv},{tz},{ug},{uz},{vc},{ve},{vn},{ws},{ye},{zm},{zw},{??}" >> /etc/tor/torrc'
sudo sh -c 'echo "ExcludeExitNodes  default,Unnamed,{ae},{af},{ag},{ao},{az},{ba},{bb},{bd},{bh},{bi},{bn},{bt},{bw},{by},{cd},{cf},{cg},{ci},{ck},{cm},{cn},{cu},{cy},{dj},{dm},{dz},{eg},{er},{et},{fj},{ga},{gd},{gh},{gm},{gn},{gq},{gy},{hr},{ht},{id},{in},{iq},{ir},{jm},{jo},{ke},{kg},{kh},{ki},{km},{kn},{kp},{kw},{kz},{la},{lb},{lc},{lk},{lr},{ly},{ma},{me},{mk},{ml},{mm},{mr},{mu},{mv},{mw},{my},{na},{ng},{om},{pg},{ph},{pk},{ps},{qa},{rs},{ru},{rw},{sa},{sb},{sd},{sg},{si},{sl},{sn},{so},{st},{sy},{sz},{td},{tg},{th},{tj},{tm},{tn},{to},{tr},{tt},{tv},{tz},{ug},{uz},{vc},{ve},{vn},{ws},{ye},{zm},{zw},{??}" >> /etc/tor/torrc'
sudo sh -c 'echo "HiddenServiceDir /var/lib/tor/hidden_service/" >> /etc/tor/torrc'
sudo sh -c 'echo "HiddenServicePort 62543 127.0.0.1:62543" >> /etc/tor/torrc'
sudo sh -c 'echo "HiddenServicePort 80 127.0.0.1:80" >> /etc/tor/torrc'
sudo sh -c 'echo "LongLivedPorts 80,62543" >> /etc/tor/torrc'
sudo /etc/init.d/tor restart
sleep 3
sudo /etc/init.d/tor stop
sleep 1
sudo touch /etc/cron.d/torcheck
sudo sh -c 'echo "*/5 * * * * root /etc/init.d/tor start > /dev/null 2>&1" >> /etc/cron.d/torcheck' ### CHECK ME or USE CRONTAB -e
sudo rm -R /var/lib/tor/hidden_service
sudo /etc/init.d/tor start
sudo echo "Tor installed, configured and restarted"
sleep 5
cd ~
sudo mv /home/pi/vulcano /home/vulcano/
sudo chown -R vulcano:vulcano /home/vulcano/vulcano/
sleep 1
sudo systemctl enable vulcanod.service
sleep 1
sudo systemctl start vulcanod.service
sleep 1
echo "externalip=`sudo cat /var/lib/tor/hidden_service/hostname`" >> /home/vulcano/.vulcanocore/vulcano.conf
sudo echo ""
sudo echo "if everything went well i should be syncing. We will check that..."
sudo echo ""
sudo echo "I will open the getinfo screen for you in watch mode, close it with CTRL + C once we are up to date, i will continue after that"
sleep 20
watch vulcano-cli -datadir=/home/vulcano/.vulcanocore -conf=/home/vulcano/.vulcanocore/vulcano.conf getinfo
sudo echo "Daemon Status:"
sudo systemctl status vulcanod.service | sed -n -e 's/^.*Active: //p'
sudo echo ""
sudo echo "Tor Status:"
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs
sudo echo ""
sudo echo "Show Onion Address:"
sudo cat /var/lib/tor/hidden_service/hostname
sudo echo ""
sudo echo "Show Active Peers:"
vulcano-cli -datadir=/home/vulcano/.vulcanocore -conf=/home/vulcano/.vulcanocore/vulcano.conf getpeerinfo | sed -n -e 's/^.*"addr" : //p'
sudo echo ""
sudo echo "Firewall Rules:"
sudo ufw status
sudo echo ""
sudo echo "Fail2Ban:"
sudo systemctl status fail2ban.service | sed -n -e 's/^.*Active: //p'
sudo echo ""
sudo echo "Unattended Updates:"
cat /etc/apt/apt.conf.d/20auto-upgrades
sleep 5
sudo echo "Installation finished. Rebooting System!"
read -p "Press any key to continue, system will reboot."
sudo reboot
