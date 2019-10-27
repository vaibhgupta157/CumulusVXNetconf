#!/bin/bash

read -s -p "Enter sudo Password: " PASSWORD

echo $PASSWORD | sudo -S -k apt-get -y install python-pip
echo $PASSWORD | sudo -S -k pip install netconf
echo $PASSWORD | sudo -S -k pip install dicttoxml

ssh-keygen -t rsa -b 2048 -f netconf-key -q -N ""


echo "export NETCONF_DIR"=$(pwd) >> ~/.bashrc
echo "NETCONF_DIR"=$(pwd) >> ~/.profile
echo $PASSWORD | sudo -S -k echo "NETCONF_DIR"=$(pwd) >> /etc/environment
source ~/.bashrc
source ~/.profile
echo "do you want to restart your computer to apply changes in /etc/environment file? yes(y)no(n)"
read restart
case $restart in
    y) echo $PASSWORD | sudo -S -k shutdown -r 0;;
    n) echo "don't forget to restart your computer manually";;
esac
exit