#include <stdio.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>	
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DHCP_HEADER_LEN 236
struct dhcp_header {
    uint8_t op;                
    uint8_t htype;            
    uint8_t hlen;               
    uint8_t hops;               
    uint32_t xid;              
    uint16_t secs;            
    uint16_t flags;          
    uint32_t ciaddr;        
    uint32_t yiaddr;       
    uint32_t siaddr;      
    uint32_t giaddr;     
    uint8_t chaddr[16]; 
    char sname[64];    
    char file[128];   
    //variable length packet below
};
void PacketExtractInformation(unsigned char* buffer , int size);
void IPExtract(unsigned char* buffer , int size);
void TCPExtract(unsigned char* buffer , int size);
void UDPExtract(unsigned char * buffer , int size);
void EthernetExtract(unsigned char* buffer);
int HTTPExtract(unsigned char * buffer, int size);
int DHCPExtract(unsigned char * buffer, int size);
void PrintRemaining (unsigned char* buffer , int size);
int sockfd;
FILE *store;
int total = 0;
int i,j;
int tplayer_tcp=0;//tcp,6
int tplayer_udp=0;//udp,17
int tplayer_icmp=0;//icmp,1
int tplayer_igmp=0;//igmp,2
int tplayer_ipinip=0;//ip in ip,4
int tplayer_rdp=0;//reliable data protocol,27
int tplayer_sctp=0;//sctp,132
int tplayer_igp=0;//interior gateway protocol,9
int tplayer_others=0;

int netlayer_arp=0;//0x0806
int netlayer_ipv4=0;//0x0800	
int netlayer_ipx=0;//0x8137
int netlayer_ipv6=0;//0x86DD
int netlayer_ppp=0;//0x880B
int netlayer_aarp=0;//0x80F3
int netlayer_others=0;

int applayer_http=0;//80
int applayer_https=0;//443
int applayer_dns=0;//53
int applayer_dhcp=0;//67,68,server,client
int applayer_dhcp6=0;//547, 546
int applayer_ftp=0;//20,21
int applayer_ssh=0;//22
int applayer_telnet=0;//23
int applayer_smtp=0;//25
int applayer_bgp=0;//179
int applayer_ipx=0;//213
int applayer_others=0;
struct sockaddr_in source,dest;

int main(int argc, char **argv){
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	store=fopen("./protocolDump.txt","w+");
	if(store==NULL) 
            printf("Can't open file to print\n");
	printf("Capturing..\n");
	//Create a raw socket that shall sniff
	sockfd = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
	if(sockfd < 0){
		perror("error opening socket:");
		return 1;
	}
        fprintf(store,"###########################################################");
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sockfd , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 ){
			printf("Receiving error\n");
			return 1;
		}
		PacketExtractInformation(buffer , data_size);
	}
	close(sockfd);
	printf("Done");
	return 0;
}

void PacketExtractInformation(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	++total;
        unsigned short ethertype;
        int breakout = 0;
        int iplength,isTCPorUDP,tplayerlength,applayerSport,applayerDport;
        struct ethhdr *eph;
        struct iphdr *iph;
        struct tcphdr *tph;
        struct udphdr *udh;

        eph = (struct ethhdr *)buffer;
        EthernetExtract(buffer);
        ethertype = ntohs(eph->h_proto);
        buffer = buffer+sizeof(struct ethhdr);
        size = size-sizeof(struct ethhdr);
        switch(ethertype){
            case 0x0806:
                breakout = 1;
                netlayer_arp += 1;
                break;
            case 0x0800:
                netlayer_ipv4 += 1;
                break;
            case 0x8137:
                breakout = 1;
                netlayer_ipx += 1;
                break;
            case 0x86DD:
                breakout = 1;
                netlayer_ipv6 += 1;
                break;
            case 0x880B:
                breakout = 1;
                netlayer_ppp += 1;
                break;
            case 0x80F3:
                breakout = 1;
                netlayer_aarp += 1;
                break;
            default:
                breakout = 1;
                netlayer_others += 1;
                break;
        }
        if(breakout){
            fprintf(store,"higher protocols not supported\n\n");
            fprintf(store,"DataLogged: Remaining hex data That doesn't belong to any recognized header\n");	
            PrintRemaining(buffer,size);
            fprintf(store,"\n###########################################################");
            fprintf(store,"\n");
            return;
        }

	iph = (struct iphdr*)buffer;
        IPExtract(buffer,size);
        iplength = iph->ihl*4;//header length
        buffer = buffer+iplength;
        size = size-iplength;
	switch (iph->protocol){
		case 1: 
                    tplayer_icmp += 1;
                    breakout = 1;
                    break;
                case 4:
                    tplayer_ipinip += 1;
                    breakout = 1;
                    break;
                case 27:
                    tplayer_rdp += 1;
                    breakout = 1;
                    break;
                case 132:
                    tplayer_sctp += 1;
                    breakout = 1;
                    break;
                case 9:
                    tplayer_igp += 1;
                    breakout = 1;
                    break;
		case 2:  
                    tplayer_igmp += 1;
                    breakout = 1;
                    break;
		case 6:  
                    tplayer_tcp += 1;
                    isTCPorUDP = 1;
                    break;
		case 17: 
                    tplayer_udp += 1;
                    isTCPorUDP = 0;
                    break;
		default: 
                    tplayer_others += 1;
                    breakout = 1;
                    break;
	}
        if(breakout){
            fprintf(store,"higher protocols not supported\n\n");
            fprintf(store,"DataLogged: Remaining hex data That doesn't belong to any recognized header\n");	
            PrintRemaining(buffer,size);
            fprintf(store,"\n###########################################################");
            return;
        }

        if(isTCPorUDP){
            tph = (struct tcphdr *)buffer;
            tplayerlength = tph->doff*4;
            applayerDport = ntohs(tph->dest);
            applayerSport = ntohs(tph->source);
            TCPExtract(buffer,size);
        }
        else{
            udh = (struct udphdr *)buffer;
            tplayerlength = sizeof(struct udphdr);
            applayerDport = ntohs(udh->dest);
            applayerSport = ntohs(udh->source);
            UDPExtract(buffer,size);
        }
        buffer = buffer+tplayerlength;
        size = size-tplayerlength;
        //one thing to remember is that just because the packet arrives at a port intended for an
        //application protocol doesn't mean that it contains that protocol header or data. Remember that
        //below application layer is tcp, and that every port is first a udp or tcp port before an 
        //application port. Data for a particular port might be just for protocols below applayer
        //Thus the below cases are just indicative rather than exact
        if(applayerSport==80||applayerDport==80){
            int tmp = HTTPExtract(buffer,size);
            buffer = buffer+tmp;
            size = size-tmp;
        }
        else if(applayerSport==68&&applayerDport==67||applayerSport==67&&applayerDport==68){
            applayer_dhcp += 1;
            int tmp = DHCPExtract(buffer,size);
            buffer = buffer+tmp;
            size = size-tmp;
        }
        else if(applayerDport==443||applayerSport==443)
            applayer_https += 1;
        else if(applayerSport==546||applayerDport==547||applayerSport==547||applayerDport==546)
            applayer_dhcp6 += 1;
        else if(applayerDport==53||applayerSport==53)
            applayer_dns += 1;
        else if(applayerDport==20||applayerDport==21||applayerSport==20||applayerSport==21)
            applayer_ftp += 1;
        else if(applayerDport==22||applayerSport==22)
            applayer_ssh += 1;
        else if(applayerSport==23||applayerDport==23)
            applayer_telnet += 1;
        else if(applayerDport==25||applayerSport==25)
            applayer_smtp += 1;
        else if(applayerDport==179||applayerSport==179)
            applayer_bgp += 1;
        else if(applayerSport==213||applayerDport==213)
            applayer_ipx += 1;
        else
            applayer_others += 1;
        fprintf(store,"DataLogged: Remaining hex data That doesn't belong to any recognized header\n");	
        PrintRemaining(buffer,size);
        fprintf(store,"\n###########################################################");
        printf("network layer:\n ARP:%d\n IPv4:%d\n IPX:%d\n IPv6:%d\n PPP:%d\n AARP:%d\n Others:%d\n\n",netlayer_arp,netlayer_ipv4,netlayer_ipx,netlayer_ipv6,netlayer_ppp,netlayer_aarp,netlayer_others);

        printf("transport layer:\n TCP:%d\n UDP:%d\n ICMP:%d\n IGMP:%d\n IPinIP:%d\n RDP:%d\n SCTP:%d\n IGP:%d\n Others:%d\n\n",tplayer_tcp,tplayer_udp,tplayer_icmp,tplayer_igmp,tplayer_ipinip,tplayer_rdp,tplayer_sctp,tplayer_igp,tplayer_others);

        printf("application layer:\n HTTP:%d\n HTTPS:%d\n DNS:%d\n DHCP:%d\n DHCPv6:%d\n FTP:%d\n SSH:%d\n TELNET:%d\n SMTP:%d\n BGP:%d\n IPX:%d\n Others:%d\n\n",applayer_http,applayer_https,applayer_dns,applayer_dhcp,applayer_dhcp6,applayer_ftp,applayer_ssh,applayer_telnet,applayer_smtp,applayer_bgp,applayer_ipx,applayer_others);

}

void IPExtract(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(store,"\n\nIP   : src IP %s",inet_ntoa(source.sin_addr));	
	fprintf(store,", dest IP %s\n",inet_ntoa(dest.sin_addr));	
	fprintf(store,"IP Version: %d\n",(unsigned int)iph->version);
	fprintf(store,"Source IP: %s\n",inet_ntoa(source.sin_addr));
	fprintf(store,"Destination IP: %s\n",inet_ntoa(dest.sin_addr));
	fprintf(store,"Protocol: %d\n",(unsigned int)iph->protocol);
	fprintf(store,"Header length in bytes: %d\n",((unsigned int)(iph->ihl))*4);
	fprintf(store,"total length in bytes: %d\n",ntohs(iph->tot_len));
	fprintf(store,"TTL: %d\n",(unsigned int)iph->ttl);
	fprintf(store,"Type Of Service: %d\n",(unsigned int)iph->tos);
	fprintf(store,"Identification: %d\n",ntohs(iph->id));
	fprintf(store,"Checksum: %d\n",ntohs(iph->check));
        fprintf(store,"\n");
}

void EthernetExtract(unsigned char* buffer){
    struct ethhdr *ehdr = (struct ethhdr*)buffer;
    fprintf(store,"\n\nETHR : Source %x:%x:%x:%x:%x:%x, Dest %x:%x:%x:%x:%x:%x\n",ehdr->h_source[0],ehdr->h_source[1],ehdr->h_source[2],ehdr->h_source[3],ehdr->h_source[4],ehdr->h_source[5],ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],ehdr->h_dest[4],ehdr->h_dest[5]);
    fprintf(store,"destination Mac: %x:%x:%x:%x:%x:%x\n",ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],ehdr->h_dest[4],ehdr->h_dest[5]);
    fprintf(store,"source Mac: %x:%x:%x:%x:%x:%x\n",ehdr->h_source[0],ehdr->h_source[1],ehdr->h_source[2],ehdr->h_source[3],ehdr->h_source[4],ehdr->h_source[5]);
    unsigned short b = ehdr->h_proto;
    unsigned char *a = (unsigned char *)&b;
    fprintf(store,"Protocol number used in network layer: %02x%02x\n",a[0],a[1]);
    fprintf(store,"\n");
}

void TCPExtract(unsigned char* Buffer, int Size)
{
	struct tcphdr *tcph=(struct tcphdr*)(Buffer);
			
	fprintf(store,"\n\nTCP  : Source Port %u, Destination Port %u, Ack No. %u, Seq No. %u\n",ntohs(tcph->source),ntohs(tcph->dest),ntohl(tcph->ack_seq),ntohl(tcph->seq));	

	fprintf(store,"Source Port: %u\n",ntohs(tcph->source));
	fprintf(store,"Destination Port: %u\n",ntohs(tcph->dest));
	fprintf(store,"Acknowledge Number: %u\n",ntohl(tcph->ack_seq));
	fprintf(store,"Sequence Number: %u\n",ntohl(tcph->seq));
	fprintf(store,"Header Length in Bytes:%d\n" ,(unsigned int)tcph->doff*4);
	fprintf(store,"Urgent Flag: %d\n",(unsigned int)tcph->urg);
	fprintf(store,"Push Flag: %d\n",(unsigned int)tcph->psh);
	fprintf(store,"Reset Flag: %d\n",(unsigned int)tcph->rst);
	fprintf(store,"Synchronise Flag: %d\n",(unsigned int)tcph->syn);
	fprintf(store,"Acknowledgement Flag: %d\n",(unsigned int)tcph->ack);
	fprintf(store,"Window: %d\n",ntohs(tcph->window));
	fprintf(store,"Checksum: %d\n",ntohs(tcph->check));
	fprintf(store,"Finish Flag: %d\n",(unsigned int)tcph->fin);
	fprintf(store,"\n");
}

void UDPExtract(unsigned char *Buffer , int Size)
{
	struct udphdr *udph = (struct udphdr*)(Buffer);
	
	fprintf(store,"\n\nUDP  : Source Port %d, Destination Port %d\n",ntohs(udph->source),ntohs(udph->dest));
	
	fprintf(store,"Source Port: %d\n" , ntohs(udph->source));
	fprintf(store,"Destination Port: %d\n" , ntohs(udph->dest));
	fprintf(store,"Length: %d\n" , ntohs(udph->len));
	fprintf(store,"Checksum: %d\n" , ntohs(udph->check));
	fprintf(store,"\n");
}

int HTTPExtract(unsigned char *buffer, int size){
    if(size == 0)//not intended for http
        return 0;
    if(buffer[0]=='G'&&buffer[1]=='E'&&buffer[2]=='T'||buffer[0]=='P'&&buffer[1]=='O'&&buffer[2]=='S'&&buffer[3]=='T'||buffer[0]=='H'&&buffer[1]=='E'&&buffer[2]=='A'&&buffer[3]=='D'||buffer[0]=='P'&&buffer[1]=='U'&&buffer[2]=='T'||buffer[0]=='D'&&buffer[1]=='E'&&buffer[2]=='L'&&buffer[3]=='E'&&buffer[4]=='T'&&buffer[5]=='E'||buffer[0]=='T'&&buffer[1]=='R'&&buffer[2]=='A'&&buffer[3]=='C'&&buffer[4]=='E'||buffer[0]=='O'&&buffer[1]=='P'&&buffer[2]=='T'&&buffer[3]=='I'&&buffer[4]=='O'&&buffer[5]=='N'&&buffer[6]=='S'||buffer[0]=='C'&&buffer[1]=='O'&&buffer[2]=='N'&&buffer[3]=='N'&&buffer[4]=='E'&&buffer[5]=='C'&&buffer[6]=='T'||buffer[0]=='P'&&buffer[1]=='A'&&buffer[2]=='T'&&buffer[3]=='C'&&buffer[4]=='H'||buffer[0]=='H'&&buffer[1]=='T'&&buffer[2]=='T'&&buffer[3]=='P'||buffer[0]=='h'&&buffer[1]=='t'&&buffer[2]=='t'&&buffer[3]=='p'){
        int i = 0;
        applayer_http += 1;
        int first = 0;
	fprintf(store,"\n\nHTTP : ");
        while(1){
            if(i>=size){
                printf("http header occupying too much\n");
                return i;
            }
            if(buffer[i]=='\r'&&buffer[i+1]=='\n'&&buffer[i+2]=='\r'&&buffer[i+3]=='\n'){
                if(!first){
                    first = 1;
                    i = 0;
                    fprintf(store,"\n");
                    continue;
                }
                fprintf(store,"\n\n");
                return i+4;
            }
            if(buffer[i]=='\r'){
                i++;
                continue;
            }
            if(buffer[i] == '\n' && !first){
                first = 1;
                i = 0;
                fprintf(store,"\n");
                continue;
            }
            fprintf(store,"%c",buffer[i]);
            i++;
        }
    }
    return 0;
}
int DHCPExtract(unsigned char *buffer, int size){
    if(size == 0){
        printf("going out because size is zero\n");
        return 0;
    }
    struct dhcp_header *dhchp = (struct dhcp_header *)buffer;
    unsigned char a = 1,b = 2;
    if(dhchp->op != a && dhchp->op != b){
        printf("going out because not a reply nor a request\n");
        return 0;
    }
    char buff[100];
    fprintf(store,"\n\nDHCP : Client hardware %x:%x:%x:%x:%x:%x, Your IP Address %s\n",dhchp->chaddr[0],dhchp->chaddr[1],dhchp->chaddr[2],dhchp->chaddr[3],dhchp->chaddr[4],dhchp->chaddr[5],inet_ntop(AF_INET,&(dhchp->yiaddr),buff,100));	

    fprintf(store,"Operation Code(1 for request, 2 for reply): %u\n",dhchp->op);
    fprintf(store,"Hardware type: %u\n",dhchp->htype);
    fprintf(store,"Hardware Address Length: %u\n",dhchp->hlen);
    fprintf(store,"Hops: %u\n",dhchp->hops);
    fprintf(store,"Transaction Identifier: %u\n" ,(unsigned int)ntohl(dhchp->xid));
    fprintf(store,"Client IP Address: %s\n",inet_ntop(AF_INET,&(dhchp->ciaddr),buff,100));
    fprintf(store,"Your IP Address: %s\n",inet_ntop(AF_INET,&(dhchp->yiaddr),buff,100));
    fprintf(store,"Server IP Address: %s\n",inet_ntop(AF_INET,&(dhchp->siaddr),buff,100));
    fprintf(store,"Gateway IP Address: %s\n",inet_ntop(AF_INET,&(dhchp->giaddr),buff,100));
    fprintf(store,"Client Hardware Address: %x:%x:%x:%x:%x:%x\n",dhchp->chaddr[0],dhchp->chaddr[1],dhchp->chaddr[2],dhchp->chaddr[3],dhchp->chaddr[4],dhchp->chaddr[5]);
    //this is assuming that it always a mac address of 48 bits
    fprintf(store,"Server Host name (Optional): %s\n",dhchp->sname);
    fprintf(store,"Boot file name (Optional): %s\n",dhchp->file);
    //server name and bootfile name will mostly be all zeros
    fprintf(store,"\n");
    return sizeof(struct dhcp_header);
}

void PrintRemaining (unsigned char* data , int total){
    for(i=0 ; i < total ; i++){
        if( i!=0 && i%16==0)
                fprintf(store,"\n");
        if(i%16==0) 
            fprintf(store,"   ");
        fprintf(store," %2x",(unsigned int)data[i]);
        if( i==total-1) 
                fprintf(store,"\n");
    }
}
