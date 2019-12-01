#!/bin/bash


echo $1 | sudo -S -k apt-get -y install gcc
echo $1 | sudo -S -k apt-get -y install git
echo $1 | sudo -S -k apt-get -y install python-dev
echo $1 | sudo -S -k apt-get -y install python-pip
echo $1 | sudo -S -k pip install netconf
echo $1 | sudo -S -k pip install dicttoxml

git clone https://github.com/robshakir/pyangbind.git

cd pynagbind && python setup.py install 

ssh-keygen -t rsa -b 2048 -f netconf-key -q -N ""


echo "export NETCONF_DIR"=$(pwd) >> ~/.bashrc
echo "NETCONF_DIR"=$(pwd) >> ~/.profile
echo $1 | sudo -S -k echo "NETCONF_DIR"=$(pwd) >> /etc/environment
source ~/.bashrc
source ~/.profile
echo "do you want to restart your computer to apply changes in /etc/environment file? yes(y)no(n)"
read restart
case $restart in
    y) echo $1 | sudo -S -k shutdown -r 0;;
    n) echo "don't forget to restart your computer manually";;
esac
exit
