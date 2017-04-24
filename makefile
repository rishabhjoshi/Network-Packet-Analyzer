all :
	gcc PacketAnalyzer.c -o analyzer
	chmod +x analyzer
	sudo setcap cap_net_raw+ep analyzer
