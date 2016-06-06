all:
	chmod +x rawhttpget
	chmod +x rawhttpget.py
setting:
	iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
