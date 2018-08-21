#!/bin/bash

sudo apt -qqy install curl
clear

# BOOTSTRAPURL=`curl -s https://api.github.com/repos/vulcanocrypto/vulcano/releases/latest | grep bootstrap.dat.xz | grep browser_download_url | cut -d '"' -f 4`
# BOOTSTRAPARCHIVE="bootstrap.dat.xz"

clear
echo "This script will refresh your masternode."
read -pr "Press Ctrl-C to abort or any other key to continue. " -n1 -s
clear

if [ -e /etc/systemd/system/vulcanod.service ]; then
    sudo systemctl stop vulcanod
else
    sudo su -c "vulcano-cli stop" vulcano
fi

echo "Refreshing node, please wait."

sleep 5

sudo rm -rf /home/vulcano/.vulcano/blocks
sudo rm -rf /home/vulcano/.vulcano/database
sudo rm -rf /home/vulcano/.vulcano/chainstate
sudo rm -rf /home/vulcano/.vulcano/peers.dat

sudo cp /home/vulcano/.vulcano/vulcano.conf /home/vulcano/.vulcano/vulcano.conf.backup

#echo "Installing bootstrap file..."
#wget $BOOTSTRAPURL && sudo xz -cd $BOOTSTRAPARCHIVE > /home/vulcano/.vulcano/bootstrap.dat && rm $BOOTSTRAPARCHIVE

if [ -e /etc/systemd/system/vulcanod.service ]; then
    sudo systemctl start vulcanod
else
    sudo su -c "vulcanod -daemon" vulcano
fi

clear

echo "Your masternode is syncing. Please wait for this process to finish."
echo "This can take up to a few hours. Do not close this window." && echo ""

# until [ -n "$(vulcano-cli getconnectioncount 2>/dev/null)"  ]; do
#     sleep 1
# done

until vulcano-cli mnsync status 2>/dev/null | grep '\"IsBlockchainSynced\" : true' >/dev/null; do
    echo -ne "Current block: $(vulcano-cli getinfo | grep blocks | awk '{print $3}' | cut -d ',' -f 1) '\\r'"
    sleep 1
done

clear

cat << EOL

Now, you need to start your masternode. If you haven't already, please add this
node to your masternode.conf now, restart and unlock your desktop wallet, go to
the Masternodes tab, select your new node and click "Start Alias."

EOL

read -rp "Press Enter to continue after you have done that. " -n1 -s

clear

sleep 1
sudo su -c "/usr/local/bin/vulcano-cli startmasternode local false" vulcano
sleep 1
clear
sudo su -c "/usr/local/bin/vulcano-cli masternode status" vulcano
sleep 5

echo "" && echo "Masternode refresh completed." && echo ""
