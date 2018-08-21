#!/bin/bash

sudo apt -qqy install curl
clear

TARBALLURL=`curl -Ls https://api.github.com/repos/VulcanoCrypto/Vulcano/releases/latest | grep browser_download_url | grep ARM | cut -d '"' -f 4`
TARBALLNAME=`curl -Ls https://api.github.com/repos/VulcanoCrypto/Vulcano/releases/latest | grep browser_download_url | grep ARM | cut -d '"' -f 4 | cut -d '/' -f 9`
VULCVERSION=`curl -Ls https://api.github.com/repos/VulcanoCrypto/Vulcano/releases/latest | grep browser_download_url | grep ARM | cut -d '"' -f 4 | cut -d '/' -f 9 | cut -d '-' -f 2`

CHARS="/-\|"

clear
echo "This script will update your Secure Home Node to version $VULCVERSION"
echo "It must be run as the 'pi' user."
read -p "Press Ctrl-C to abort or any other key to continue. " -n1 -s
clear

echo "Shutting down masternode..."
sudo systemctl stop vulcanod

echo "Installing Vulcano $VULCVERSION..."
mkdir ./vulcano-temp && cd ./vulcano-temp
wget $TARBALLURL
tar -xzvf $TARBALLNAME
yes | sudo cp -rf ./vulcano-$VULCVERSION/vulcanod /usr/local/bin
yes | sudo cp -rf ./vulcano-$VULCVERSION/vulcano-cli /usr/local/bin
cd ..
rm -rf ./vulcano-temp

# Remove addnodes from vulcano.conf
#sudo sed -i '/^addnode/d' /home/vulcano/.vulcano/vulcano.conf

# Add Fail2Ban memory hack if needed
if ! grep -q "ulimit -s 256" /etc/default/fail2ban; then
    echo "ulimit -s 256" | sudo tee -a /etc/default/fail2ban
    sudo systemctl restart fail2ban
fi

sudo systemctl start vulcanod

clear

echo "Your masternode is syncing. Please wait for this process to finish."

until sudo su -c "vulcano-cli mnsync status 2>/dev/null | grep '\"IsBlockchainSynced\" : true' > /dev/null" vulcano; do
    for (( i=0; i<${#CHARS}; i++ )); do
        sleep 2
        echo -en "${CHARS:$i:1}" "\r"
    done
done

clear

cat << EOL

Now, you need to start your masternode. If you haven't already, please add this
node to your masternode.conf now, restart and unlock your desktop wallet, go to
the Masternodes tab, select your new node and click "Start Alias."

EOL

read -p "Press Enter to continue after you've done that. " -n1 -s

clear

sudo su -c "vulcano-cli masternode status" vulcano

cat << EOL

Secure Home Node update completed.

EOL
