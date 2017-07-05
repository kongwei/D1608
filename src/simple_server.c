#include <string.h>
#include <stdio.h>
#include "enc28j60.h"
#include "ip_arp_udp_tcp.h"
#include "net.h"
#include "simple_server.h"
#include "stm32f10x_flash.h"

#define BUFFER_SIZE 1500

extern unsigned long int iap_ip_address;
extern Flash_Data myip;
const unsigned char equip_id[10] = "SMCXXXX";
const unsigned char xor_key[17] = "江苏南京联盛科技";

uint32_t FlashDestination, flash_length; 
uint32_t RamSource;

extern unsigned char mymac[6];
#pragma pack(1)
		typedef struct
		{
			char ip[4];
			char id[10];
			char name[26];
			char flag3[64];
			char type[16];
			char ser[16];
			char ver[36];
			char mac[6];
			char mask[4];
			char gateway[4];
			short port;
			unsigned int cpu_id[3];		//
		}T_slp_pack;

#define active_code_length 20
#define SN_START_PAGE (0x0803E800)
    typedef struct
    {
        char sn[20];
        char type[20];
        char default_device_name[20];
        char name1[24];
        char name2[24];
        char hardware_name[16];
        char active_code[20];
    }T_sn_pack;
#pragma pack()

extern u32 CpuID[3];

void simple_server_start(void)
{
	static unsigned char iap_state = 0;
	static unsigned char buf[BUFFER_SIZE+1];
	unsigned int plen;
	unsigned int EraseCounter;
	
	union
	{
		unsigned long int data_32;
		unsigned char data_8[4];
	} package_size;

	//判断是否有接收到有效的包
	plen = enc28j60PacketReceive(BUFFER_SIZE, buf);
	//如果收到有效的包，plen将为非0值。
	if (plen == 0)
	{
		//没有收到有效的包就退出重新检测
		return;
	}
	//当收到目的地址为本机IP的ARP包时，发出ARP相应包
	if (eth_type_is_arp_and_my_ip(buf, plen))
	{
		make_arp_answer_from_request(buf);
		return;
	}

	//判断是否接收到目的地址为本机IP的合法的IP包
	if (eth_type_is_ip_and_my_ip(buf, plen) == 0)
	{
		return;
	}
	//如果收到ICMP包
	if ((buf[IP_PROTO_P] == IP_PROTO_ICMP_V) && (buf[ICMP_TYPE_P] == ICMP_TYPE_ECHOREQUEST_V))
	{
		// printf("\n\r收到主机[%d.%d.%d.%d]发送的ICMP包",buf[ETH_ARP_SRC_IP_P],buf[ETH_ARP_SRC_IP_P+1],
		//                                               buf[ETH_ARP_SRC_IP_P+2],buf[ETH_ARP_SRC_IP_P+3]);
		make_echo_reply_from_request(buf, plen);
		return;
	}

	//UDP包，监听666端口的UDP包
	if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0x02) && (buf[UDP_DST_PORT_L_P] == 0x9A))
	{
		if (memcmp(buf+UDP_DATA_P, "ver", 3) == 0)
		{
			T_slp_pack * p_reply = (T_slp_pack*)(buf+UDP_DATA_P);
			memset(p_reply, 0, sizeof(T_slp_pack));

			// 如果收到报文的ip地址的前3字节不同，那么进入跟随ip地址模式
			if (memcmp(myip.data_8, buf+IP_SRC_P, 3) != 0)
			{
				memcpy(myip.data_8, buf+IP_SRC_P, 4);
				// IP结尾为10或者18
				if (myip.data_8[3] == 10)
					myip.data_8[3] = 18;
				else
					myip.data_8[3] = 10;
				
				init_ip_arp_udp_tcp(mymac, myip.data_8, 0);
			}

			p_reply->cpu_id[0] = *(vu32*)(0x1ffff7e8);
			p_reply->cpu_id[1] = *(vu32*)(0x1ffff7ec);
			p_reply->cpu_id[2] = *(vu32*)(0x1ffff7f0);

			memcpy(p_reply->ip, myip.data_8, 4);
			snprintf(p_reply->name, 25, "%s", equip_id);
			snprintf(p_reply->id, 10, "%02X%02X%02X", mymac[3], mymac[4], mymac[5]);
			snprintf(p_reply->ver, 35, "%s %s", __DATE__, __TIME__);

			//memcpy(p_reply->mac, mymac, 6);

			make_udp_reply_with_data(buf, sizeof(T_slp_pack), 888);
			

			//memcpy(buf+UDP_DATA_P, myip.data_8, 4);
			//memcpy(buf+UDP_DATA_P+4, equip_id, 10);

			//make_udp_reply_with_data(buf, 14, 888);
		}
	}
	// 8754
	else if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0x22) && (buf[UDP_DST_PORT_L_P] == 0x32))
	{
		int length = buf[UDP_LEN_H_P] << 8 | buf[UDP_LEN_L_P];
		if (length < 256+12)
		{
			return;
		}
		
		if (buf[UDP_DATA_P] == ' ' && buf[UDP_DATA_P+1] == ' ')
		{
			int i;
			for (i=0;i<256;i++)
			{
				char * p_sign = (char*)0x0803E400+i;
				if (p_sign[0] != 0xFF)
				{
					break;
				}
			}
			if (i == 256)
			{
				// 返回校验码
				memcpy(buf+UDP_DATA_P, (char*)0x0803E400, 256);
				memcpy(buf+UDP_DATA_P+256, CpuID, 12);
				make_udp_reply_with_data(buf, 256+12, 8754);
			}
		}
		else if (memcmp(CpuID, buf+UDP_DATA_P+256, 12) == 0)
		{
			// 写rsa加密后的校验码
			int i;
			FLASH_ErasePage(0x0803E400);

			for (i = 0; i < 256; i += 4)
			{
				// xor处理
				uint32_t write_data = *(uint32_t*)(buf+UDP_DATA_P+i);

				//把接收到的数据编写到Flash中
				FLASH_ProgramWord(0x0803E400+i, write_data);
			}
		}
	}
	else if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0x03) && (buf[UDP_DST_PORT_L_P] == 0x79))
	{
		int i;
		//T_sn_pack * p_sn = (T_sn_pack*)(buf+UDP_DATA_P);
		
		FLASH_Unlock();
		FLASH_ErasePage(SN_START_PAGE);

		for (i = 0; i<sizeof(T_sn_pack); i+=4)
		{
			uint32_t data = *(uint32_t*)(buf+UDP_DATA_P+i);
			FLASH_ProgramWord(SN_START_PAGE + i + active_code_length, data);
		}
	}
	else if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0xff) && (buf[UDP_DST_PORT_L_P] == 0xee))
	{
		// 是否激活
		T_sn_pack * p_sn_pack = (T_sn_pack*)(SN_START_PAGE+active_code_length);
		if (p_sn_pack->active_code[0]==0xFF && p_sn_pack->active_code[1]==0xFF)
		{
			memcpy(buf+UDP_DATA_P, "err", 3);
			make_udp_reply_with_data(buf, 3, 65518);
			return;
		}
		
		if (memcmp(buf+UDP_DATA_P, "opt", 3) == 0)
		{
			if (iap_state == 0x01)
			{
				iap_state = 0x00;
				memcpy(buf+UDP_DATA_P, "Too Big!!", 9);

				make_udp_reply_with_data(buf, 9, 65518);
			}
			else if (iap_state == 0x05)
			{
				iap_state = 0x00;
				memcpy(buf+UDP_DATA_P, "Not Data!", 9);

				make_udp_reply_with_data(buf, 9, 65518);
			}
			else if (iap_state == 0x12)
			{
				iap_state = 0x10;
				memcpy(buf+UDP_DATA_P, "Flash_Erase_ok", 14);

				make_udp_reply_with_data(buf, 14, 65518);
			}
			else if (iap_state == 0x13)
			{
				iap_state = 0x10;
				memcpy(buf+UDP_DATA_P, "Flash write ok", 14);

				make_udp_reply_with_data(buf, 14, 65518);
			}
			else if (iap_state ==0x14)
			{
				iap_state = 0x10;
				memcpy(buf+UDP_DATA_P, "Flash writeerr", 14);

				make_udp_reply_with_data(buf, 14, 65518);
			}
			else if (iap_state == 0x26)
			{
				FLASH_Status FLASHStatus;
				iap_state = 0x20;
				FLASHStatus = FLASH_ErasePage(iap_ip_address);
				if (FLASHStatus == FLASH_COMPLETE)
				{
					memcpy(buf+UDP_DATA_P, "I will jump ok", 14);

					make_udp_reply_with_data(buf, 14, 65518);
					
					NVIC_SystemReset();
				}
				else
				{
					memcpy(buf+UDP_DATA_P, "Flash writeerr", 14);

					make_udp_reply_with_data(buf, 14, 65518);
				}
			}
		}
		else if (memcmp(buf+UDP_DATA_P, "err", 3) == 0)
		{
			iap_state = 0x00;
		}
		else
		{
			unsigned int payloadlen;
			payloadlen = buf[UDP_LEN_H_P];
			payloadlen = payloadlen<<8;
			payloadlen = payloadlen + buf[UDP_LEN_L_P] - UDP_HEADER_LEN;

			//make_udp_reply_with_data(buf, payloadlen, 65518);

			{
				iap_state &= 0xf0;

				if (iap_state == 0x00)
				{
					if (memcmp(buf+UDP_DATA_P, "iap_start", 9) == 0)
					{
						make_udp_reply_with_data(buf, payloadlen, 65518);
						
						memcpy(package_size.data_8, buf+UDP_DATA_P+9, 4);
						flash_length = package_size.data_32;
						if (package_size.data_32 > 128*1024)//51200
						{
							//too big
							iap_state = 0x01;
						}
						else
						{
							unsigned int NbrOfPage;
							FLASH_Status FLASHStatus = FLASH_COMPLETE;

							//计算需要擦除Flash的页
							//NbrOfPage = (package_size.data_32 + PAGE_SIZE - 1) / PAGE_SIZE;
							// 固定擦除100k
							NbrOfPage = 60;

							FlashDestination = ApplicationAddress;

							//擦除Flash
							for (EraseCounter = 0;
								(EraseCounter < NbrOfPage) && (FLASHStatus == FLASH_COMPLETE);
								EraseCounter++)
							{
								FLASHStatus = FLASH_ErasePage(ApplicationAddress + (PAGE_SIZE * EraseCounter));
							}

							//flash erase ok
							iap_state = 0x12;
						}
					}
					else if (memcmp(buf+UDP_DATA_P, "iap", 3) != 0)
					{
						iap_state = 0;
						memcpy(buf+UDP_DATA_P, "err", 3);
						make_udp_reply_with_data(buf,3,65518);
					}
					else
					{
						// 校验硬件
						T_sn_pack * p_sn_pack = (T_sn_pack*)(SN_START_PAGE+active_code_length);
						char hardware_verify[16];
						
						memcpy(hardware_verify, p_sn_pack->hardware_name, sizeof(hardware_verify));
						// 是否能匹配硬件名称
						if ((memcmp("|XXXX|", hardware_verify, 6) != 0) 
							&& (strstr((char*)buf+UDP_DATA_P, hardware_verify) == NULL)
							&& (memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", hardware_verify, 6) != 0) )
						{
							iap_state = 0;
							memcpy(buf+UDP_DATA_P, "err", 3);
							make_udp_reply_with_data(buf,3,65518);
						}
						else
						{
							make_udp_reply_with_data(buf, payloadlen, 65518);
						}
					}
				}
				else if (iap_state == 0x10)
				{
					make_udp_reply_with_data(buf, payloadlen, 65518);
					if (memcmp(buf+UDP_DATA_P, "iap_data:", 9) == 0)
					{
						memcpy(package_size.data_8, buf+UDP_DATA_P+9, 4);
						//write flash ok;
						iap_state = 0x13;
						RamSource = (uint32_t)(buf + UDP_DATA_P + 13);

						{
							for (EraseCounter = 0; 
								EraseCounter < package_size.data_32 && FlashDestination <  ApplicationAddress + flash_length;
								EraseCounter+=4)
							{
								// xor处理
								uint32_t write_data = *(uint32_t*)RamSource;
								uint32_t xor_data = *(uint32_t*)(xor_key + (EraseCounter % 16));
								write_data = write_data ^ xor_data ^ 0x55aa4774;

								//把接收到的数据编写到Flash中
								FLASH_ProgramWord(FlashDestination, write_data);

								if (*(uint32_t*)FlashDestination != write_data)
								{
									//write flash err;
									iap_state = 0x14;
								}
								FlashDestination += 4;
								RamSource += 4;
							}
						}
					}
					else if (memcmp(buf+UDP_DATA_P, "iap_end", 7) == 0)
					{
						iap_state = 0x26;
					}
					else
					{
						//write flash ok;
						iap_state = 0x05;
					}
				}
				else
				{
					make_udp_reply_with_data(buf, payloadlen, 65518);
					iap_state = 0x00;
				}
			}
		}
	}
	return;
}
