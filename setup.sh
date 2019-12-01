#!/bin/bash


echo $1 | sudo -S -k apt-get -y install gcc
echo $1 | sudo -S -k apt-get -y install python-dev
echo $1 | sudo -S -k apt-get -y install python-pip
echo $1 | sudo -S -k pip install netconf
echo $1 | sudo -S -k pip install dicttoxml


echo $1 | sudo -S -k python pyangbind/setup.py install 

ssh-keygen -t rsa -b 2048 -f netconf-key -q -N ""


echo "export NETCONF_DIR"=$(pwd) >> ~/.bashrc
echo "NETCONF_DIR"=$(pwd) >> ~/.profile
echo "NETCONF_DIR"=$(pwd) | sudo tee -a /etc/environment
source ~/.bashrc
source ~/.profile
echo "do you want to restart your computer to apply changes in /etc/environment file? yes(y)no(n)"
read restart
case $restart in
    y) echo $1 | sudo -S -k shutdown -r 0;;
    n) echo "don't forget to restart your computer manually";;
esac
exit
