# netops-home
NetOps home lab bootstrap and automation


Bootstrap commands:
curl -fsSL https://raw.githubusercontent.com/Belelusat/netops-home/main/bootstrap/bootstrap.sh -o bootstrap.sh
curl -fsSL https://raw.githubusercontent.com/Belelusat/netops-home/main/bootstrap/bootstrap.vars -o bootstrap.vars
sudo bash bootstrap.sh --vars bootstrap.vars
