
#include "ip_arp_udp_tcp.h"
#include "net.h"
#include "enc28j60.h"
#include <stdio.h>

static unsigned char macaddr[6];
static unsigned char ipaddr[4];

// The Ip checksum is calculated over the ip header only starting
// with the header length field and a total length of 20 bytes
// unitl ip.dst
// You must set the IP checksum field to zero before you start
// the calculation.
// len for ip is 20.
//
// For UDP/TCP we do not make up the required pseudo header. Instead we 
// use the ip.src and ip.dst fields of the real packet:
// The udp checksum calculation starts with the ip.src field
// Ip.src=4bytes,Ip.dst=4 bytes,Udp header=8bytes + data length=16+len
// In other words the len here is 8 + length over which you actually
// want to calculate the checksum.
// You must set the checksum field to zero before you start
// the calculation.
// len for udp is: 8 + 8 + data length
// len for tcp is: 4+4 + 20 + option len + data length
//
// For more information on how this algorithm works see:
// http://www.netfor2.com/checksum.html
// http://www.msc.uky.edu/ken/cs471/notes/chap3.htm
// The RFC has also a C code example: http://www.faqs.org/rfcs/rfc1071.html
unsigned  int checksum(unsigned char *buf, unsigned  int len,unsigned char type)
{
	// type 0=ip 
	//      1=udp
	//      2=tcp
	unsigned long sum = 0;
	
	//if(type==0){
	//        // do not add anything
	//}
	if(type==1)
	{
		sum+=IP_PROTO_UDP_V; // protocol udp
		// the length here is the length of udp (data+header len)
		// =length given to this function - (IP.scr+IP.dst length)
		sum+=len-8; // = real tcp len
	}
	if(type==2)
	{
		sum+=IP_PROTO_TCP_V; 
		// the length here is the length of tcp (data+header len)
		// =length given to this function - (IP.scr+IP.dst length)
		sum+=len-8; // = real tcp len
	}
	// build the sum of 16bit words
	while(len >1)
	{
		sum += 0xFFFF & (*buf<<8|*(buf+1));
		buf+=2;
		len-=2;
	}
	// if there is a byte left then add it (padded with zero)
	if (len)
	{
		sum += (0xFF & *buf)<<8;
	}
	// now calculate the sum over the bytes in the sum
	// until the result is only 16bit long
	while (sum>>16)
	{
		sum = (sum & 0xFFFF)+(sum >> 16);
	}
	// build 1's complement:
	return( (unsigned  int) sum ^ 0xFFFF);
}

// you must call this function once before you use any of the other functions:
void init_ip_arp_udp_tcp(unsigned char *mymac,unsigned char *myip,unsigned char wwwp)
{
	unsigned char i=0;
	while(i<4)
	{
        ipaddr[i]=myip[i];
        i++;
	}
	i=0;
	while(i<6)
	{
        macaddr[i]=mymac[i];
        i++;
	}
}
/*----------------------------------------------------------------------------------
当收到目的IP为本机IP的ARP包时，返回值为1，否则返回0
-----------------------------------------------------------------------------------*/
unsigned char eth_type_is_arp_and_my_ip(unsigned char *buf,unsigned  int len)
{
	unsigned char i=0;
    //包长度不够，直接返回
	if (len<41)
	{
	    return(0);
	}

    //如果类型不是ARP包，直接返回
	if(buf[ETH_TYPE_H_P] != ETHTYPE_ARP_H_V || buf[ETH_TYPE_L_P] != ETHTYPE_ARP_L_V)
	{
	    return(0);
	}

    //如果ARP包的IP地址与本机IP不一致，直接返回
	while(i<4)
	{
	    if(buf[ETH_ARP_DST_IP_P+i] != ipaddr[i])
		{
	        return(0);
	    }
	    i++;
	}
   // printf("\n\r收到主机[%d.%d.%d.%d]发送的ARP包",buf[ETH_ARP_SRC_IP_P],buf[ETH_ARP_SRC_IP_P+1],buf[ETH_ARP_SRC_IP_P+2],buf[ETH_ARP_SRC_IP_P+3]);
    
	return(1);
}

unsigned char eth_type_is_ip_and_my_ip(unsigned char *buf,unsigned  int len)
{
	unsigned char i=0;
    //包长度不够，直接返回
	if (len<42)
	{
	    return(0);
	}
    
    //如果包类型不是IP包，直接返回
	if(buf[ETH_TYPE_H_P]!=ETHTYPE_IP_H_V || buf[ETH_TYPE_L_P]!=ETHTYPE_IP_L_V)
	{

        return(0);
	}
    //如果长度参数不正确，直接返回
	if (buf[IP_HEADER_LEN_VER_P]!=0x45)
	{
	    // must be IP V4 and 20 byte header
	    return(0);
	}
    
    //如果IP包的IP地址与本机IP不一致，直接返回    
	while(i<4)
	{
	    if(buf[IP_DST_P+i]!=ipaddr[i]& buf[IP_DST_P+i]!=255)
		{
	        return(0);
	    }
	    i++;
	}
	return(1);
}

// make a return eth header from a received eth packet
void make_eth(unsigned char *buf)
{
	unsigned char i=0;

	//填写包的目的MAC地址，以及源MAC地址
	while(i<6)
	{
        buf[ETH_DST_MAC +i]=buf[ETH_SRC_MAC +i];
        buf[ETH_SRC_MAC +i]=macaddr[i];
        i++;
	}
}
void fill_ip_hdr_checksum(unsigned char *buf)
{
	unsigned  int ck;
	// clear the 2 byte checksum
	buf[IP_CHECKSUM_P]=0;
	buf[IP_CHECKSUM_P+1]=0;
	buf[IP_FLAGS_P]=0x40; // don't fragment
	buf[IP_FLAGS_P+1]=0;  // fragement offset
	buf[IP_TTL_P]=64; // ttl
	// calculate the checksum:
	ck=checksum(&buf[IP_P], IP_HEADER_LEN,0);
	buf[IP_CHECKSUM_P]=ck>>8;
	buf[IP_CHECKSUM_P+1]=ck& 0xff;
}

// make a return ip header from a received ip packet
void make_ip(unsigned char *buf)
{
	unsigned char i=0;
	while(i<4)
	{
        buf[IP_DST_P+i]=buf[IP_SRC_P+i];
        buf[IP_SRC_P+i]=ipaddr[i];
        i++;
	}
	fill_ip_hdr_checksum(buf);
}

void make_arp_answer_from_request(unsigned char *buf)
{
	unsigned char i=0;
    
	//填写包的目的MAC地址以及源MAC地址	
	make_eth(buf); 
    
    //填写ARP响应包的类型
	buf[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REPLY_H_V;   //arp 响应
	buf[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REPLY_L_V;

    //填写ARP包的目的MAC地址以及源MAC地址
	while(i<6)
	{
        buf[ETH_ARP_DST_MAC_P+i]=buf[ETH_ARP_SRC_MAC_P+i];
        buf[ETH_ARP_SRC_MAC_P+i]=macaddr[i];
        i++;
	}

    //填写ARP包的目的IP地址以及源IP地址    
	i=0;
	while(i<4)
	{
        buf[ETH_ARP_DST_IP_P+i]=buf[ETH_ARP_SRC_IP_P+i];
        buf[ETH_ARP_SRC_IP_P+i]=ipaddr[i];
        i++;
	}

   // printf("\n\r[%d.%d.%d.%d]发送ARP相应",ipaddr[0],ipaddr[1],ipaddr[2],ipaddr[3]);

    //发送ARP相应包
	enc28j60PacketSend(42,buf); 
}

void make_echo_reply_from_request(unsigned char *buf,unsigned  int len)
{
	//填写包的目的MAC地址以及源MAC地址	
	make_eth(buf);
	//填写包的目的IP地址以及源IP地址	
	make_ip(buf);

    //填写ICMP相应包类型
	buf[ICMP_TYPE_P]=ICMP_TYPE_ECHOREPLY_V;	  //////回送应答////////////////////////////////////////////////////////////////////////////

    // we changed only the icmp.type field from request(=8) to reply(=0).
	// we can therefore easily correct the checksum:
	if (buf[ICMP_CHECKSUM_P] > (0xff-0x08))
	{
	    buf[ICMP_CHECKSUM_P+1]++;
	}
	buf[ICMP_CHECKSUM_P]+=0x08;

   // printf("\n\r[%d.%d.%d.%d]发送ICMP包响应",ipaddr[0],ipaddr[1],ipaddr[2],ipaddr[3]);

    //发送ICMP响应包
	enc28j60PacketSend(len,buf);
}

// you can send a max of 220 bytes of data
void make_udp_reply_from_request(unsigned char *buf,char *data,unsigned int datalen,unsigned  int port)
{
	// copy the data:
	int i = 0;
	while(i<datalen)
	{
        buf[UDP_DATA_P+i]=data[i];
        i++;
	}
	make_udp_reply_with_data(buf, datalen, port);
}

void make_udp_reply_with_data(unsigned char *buf,unsigned int datalen,unsigned  int port)
{
	unsigned int i=0;
	unsigned  int ck;
	make_eth(buf);
	
	// total length field in the IP header must be set:
	i= IP_HEADER_LEN+UDP_HEADER_LEN+datalen;
	buf[IP_TOTLEN_H_P]=i>>8;
	buf[IP_TOTLEN_L_P]=i;
	make_ip(buf);

	buf[UDP_DST_PORT_H_P]=buf[UDP_SRC_PORT_H_P];
	buf[UDP_DST_PORT_L_P]=buf[UDP_SRC_PORT_L_P];
    buf[UDP_SRC_PORT_H_P]=port>>8;
	buf[UDP_SRC_PORT_L_P]=port & 0xff;
	// source port does not matter and is what the sender used.
	// calculte the udp length:
	buf[UDP_LEN_H_P]=(UDP_HEADER_LEN+datalen)>>8;
	buf[UDP_LEN_L_P]=(UDP_HEADER_LEN+datalen)& 0xff;
	// zero the checksum
	buf[UDP_CHECKSUM_H_P]=0;
	buf[UDP_CHECKSUM_L_P]=0;
	
	ck=checksum(&buf[IP_SRC_P], 16 + datalen,1);
	buf[UDP_CHECKSUM_H_P]=ck>>8;
	buf[UDP_CHECKSUM_L_P]=ck& 0xff;

	enc28j60PacketSend(UDP_HEADER_LEN+IP_HEADER_LEN+ETH_HEADER_LEN+datalen,buf);
}
