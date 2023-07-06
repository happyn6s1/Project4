# Project4
 
sudo apt install gcc -y  
sudo apt install zsh -y  
sudo apt install make -y  
sudo apt install tree -y  
sudo apt install openssh-server -y  
#  
sudo apt update -y  
sudo apt upgrade -y  
sudo apt autoremove -y  
#  
sudo apt install python3-pip  
sudo apt install python3-flask -y  
sudo apt install nginx -y  
sudo apt install net-tools -y  
sudo apt install git -y  
#  
sudo systemctl enable ssh  
sudo ufw allow ssh  
sudo ln -s /usr/bin/python3.11 /usr/bin/python  
pip install flask_restful --break-system-packages  
pip install --upgrade requests --break-system-packages  
pip install --upgrade urllib3 --break-system-packages
pip install --upgrade cryptography --break-system-packages  
pip install --upgrade certifi --break-system-packages  

#sudo su  
#Copy nginx.tar.gz to /etc/  
cd /etc  
tar -xvf ./nginx.tar.gz  

#Make server scripts executable
chmod +x /home/cs6238/Desktop/Project4/server/application/start_server.sh  
chmod +x /home/cs6238/Desktop/Project4/server/application/stop_server.sh  


#Add secure-shared-store to the hosts file  
sudo su  
echo "127.0.0.1 secure-shared-store" >> /etc/hosts  

#Now you can install the Guest Additions from the Devices Menu in VirtualBox  
#Optional -> Change your network to Bridge then:  
sudo systemctl restart NetworkManager.service  
sudo ip link show  
sudo ip link set enp0s3 down  
sudo ip link set enp0s3 up  

#Optional Software
sudo snap install pycharm-communicty --classic  
