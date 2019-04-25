# firewall
###### *DISLAIMER: The following code is only for Ubuntu.*

### Features
1) Block IP adderesses
2) Block access to certain ports 
3) Block specifed prefiexes of IP address (to block networks)
4) Block too many requests made by the same IP in a short period of time (user can specify threshold and time)

### Steps to Run
1) Type the following terminal command: 
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
2) Fill out the rules in the JSON file as follows:
<br><img src = "/screenshots/config.PNG" width="50%"></img><br>
3) Execute firewall.py using python3

### Requirements
1) netfilterqueue
2) scapy

### Credits:
1) Meghana Holla : https://github.com/meghana-holla
1) Ornella D'suoza : https://github.com/Onurene

### Author

1) Email: nishant.aklecha@gmail.com
2) LinkedIn: https://www.linkedin.com/in/naklecha
3) CodeChef: https://www.codechef.com/users/naklecha
4) PYPI: https://pypi.org/user/naklecha
5) GitHub: https://github.com/Naklecha

##### *"Any suggestions would be appreciated"*
