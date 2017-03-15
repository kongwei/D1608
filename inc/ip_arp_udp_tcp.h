/*********************************************
 * vim:sw=8:ts=8:si:et
 * To use the above modeline in vim you must have "set modeline" in your .vimrc
 * Author: Guido Socher 
 * Copyright: GPL V2
 *
 * IP/ARP/UDP/TCP functions
 *
 * Chip type           : ATMEGA88 with ENC28J60
 *********************************************/


/*********************************************
 * modified: 2007-08-08
 * Author  : awake
 * Copyright: GPL V2
 * http://www.icdev.com.cn/?2213/
 * Host chip: ADUC7026
**********************************************/



//@{
#ifndef IP_ARP_UDP_TCP_H
#define IP_ARP_UDP_TCP_H

// you must call this function once before you use any of the other functions:
void init_ip_arp_udp_tcp(unsigned char *mymac,unsigned char *myip,unsigned char wwwp);
unsigned char eth_type_is_arp_and_my_ip(unsigned char *buf,unsigned int len);
unsigned char eth_type_is_ip_and_my_ip(unsigned char *buf,unsigned int len);
void make_arp_answer_from_request(unsigned char *buf);
void make_echo_reply_from_request(unsigned char *buf,unsigned int len);
// void make_udp_reply_from_request(unsigned char *buf,char *data,unsigned int datalen,unsigned int port);
void make_udp_reply_with_data(unsigned char *buf,unsigned int datalen,unsigned  int port);

#endif /* IP_ARP_UDP_TCP_H */
//@}
