#include <string.h>
#include <stdio.h>
#include "enc28j60.h"
#include "ip_arp_udp_tcp.h"
#include "net.h"
#include "simple_server.h"
#include "stm32f10x_flash.h"
#include <absacc.h>

#define BUFFER_SIZE 1500

extern unsigned long int iap_ip_address;
extern Flash_Data myip;
const unsigned char equip_id[10] = "SMCXXXX";
const unsigned char xor_key[17] = "江苏南京联盛科技";

#ifndef DEBUG_VERSION
const char MyText[] __at (0x08001F00) = __DATE__" "__TIME__;
#else
const char MyText[] __at (0x08001F00) = "                  ";
#endif

uint32_t FlashDestination, flash_length; 

extern unsigned char mymac[6];
#pragma pack(1)
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
		unsigned int mask;
		char gateway[4];
		short port;
		unsigned int cpu_id[3];		//
		T_sn_pack sn_info;
	}T_slp_pack;

#define active_code_length 20
#define SN_START_PAGE (0x0803E800)
#pragma pack()

static char last_1k_cache[2048]; // 前1024缓存，后1024拼接数据
static int last_1k_cache_size = 0;

static int GetCurrentPoint()
{
	return FlashDestination + last_1k_cache_size - ApplicationAddress;
}
	
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
			unsigned int sr_ip = (*(int*)(buf+IP_SRC_P));

			if (p_reply->mask == 0)
				p_reply->mask = 0x00FFFFFF;
			// 兼容早起版本
			if ( *(buf+UDP_LEN_H_P) == 0 && *(buf+UDP_LEN_H_P)<10 )
				p_reply->mask = 0x00FFFFFF;
			
			// 如果收到报文的ip地址的前3字节不同，那么进入跟随ip地址模式
			if ( (myip.data_32 & p_reply->mask) != (sr_ip & p_reply->mask) )
			{
				memcpy(myip.data_8, buf+IP_SRC_P, 4);
				// IP结尾为10或者18
				if (myip.data_8[3] == 10)
					myip.data_8[3] = 18;
				else
					myip.data_8[3] = 10;
				
				init_ip_arp_udp_tcp(mymac, myip.data_8, 0);
			}

			memset(p_reply, 0, sizeof(T_slp_pack));
			p_reply->cpu_id[0] = *(vu32*)(0x1ffff7e8);
			p_reply->cpu_id[1] = *(vu32*)(0x1ffff7ec);
			p_reply->cpu_id[2] = *(vu32*)(0x1ffff7f0);

			memcpy(p_reply->ip, myip.data_8, 4);
			snprintf(p_reply->name, 25, "%s", equip_id);
			snprintf(p_reply->id, 10, "%02X%02X%02X", mymac[3], mymac[4], mymac[5]);
			snprintf(p_reply->ver, 35, "%s", MyText);

			//memcpy(p_reply->mac, mymac, 6);
			memcpy(&p_reply->sn_info, (char*)SN_START_PAGE + active_code_length, sizeof(p_reply->sn_info));

			make_udp_reply_with_data(buf, sizeof(T_slp_pack), 888);
			

			//memcpy(buf+UDP_DATA_P, myip.data_8, 4);
			//memcpy(buf+UDP_DATA_P+4, equip_id, 10);

			//make_udp_reply_with_data(buf, 14, 888);
		}
	}
	// 8754
	else if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0x22) && (buf[UDP_DST_PORT_L_P] == 0x32))
	{
		int udp_len = buf[UDP_LEN_H_P] << 8 | buf[UDP_LEN_L_P];
		if (udp_len < 256+12)
		{
			return;
		}
		
		if (buf[UDP_DATA_P] == ' ' && buf[UDP_DATA_P+1] == ' ')
		{
			int i;
			for (i=0;i<256;i++)
			{
				char * p_sign = (char*)SN_START_PAGE+1024+i;
				if (p_sign[0] != 0xFF)
				{
					break;
				}
			}
			if (i == 256)
			{
				// 返回CpuId和校验码
				memcpy(buf+UDP_DATA_P, (char*)SN_START_PAGE+1024, 256);
				memcpy(buf+UDP_DATA_P+256, CpuID, 12);
				make_udp_reply_with_data(buf, 256+12, 8754);
			}
		}
		else if (memcmp(CpuID, buf+UDP_DATA_P+256, 12) == 0)
		{
			// 写rsa加密后的校验码
			int i;
			
			char sn_pack_buf[1024-active_code_length];
			memcpy(sn_pack_buf, (char*)SN_START_PAGE + active_code_length, sizeof(sn_pack_buf));
			
			FLASH_Unlock();
			FLASH_ErasePage(SN_START_PAGE+1024);

			for (i = 0; i < 256; i += 4)
			{
				uint32_t write_data = *(uint32_t*)(buf+UDP_DATA_P+i);
				FLASH_ProgramWord(SN_START_PAGE+1024+i, write_data);
			}

			for (i = 0; i<sizeof(sn_pack_buf); i+=4)
			{
				uint32_t data = *(uint32_t*)(sn_pack_buf+i);
				FLASH_ProgramWord(SN_START_PAGE + i + active_code_length, data);
			}
		}
	}
	else if ((buf[IP_PROTO_P] == IP_PROTO_UDP_V) && (buf[UDP_DST_PORT_H_P] == 0x03) && (buf[UDP_DST_PORT_L_P] == 0x79))
	{
		int i;
		int udp_len = buf[UDP_LEN_H_P]<<8|buf[UDP_LEN_L_P];
		//T_sn_pack * p_sn = (T_sn_pack*)(buf+UDP_DATA_P);
		char rsa_buf[1024];
		memcpy(rsa_buf, (char*)SN_START_PAGE + 1024, sizeof(rsa_buf));
		
		FLASH_Unlock();
		FLASH_ErasePage(SN_START_PAGE);

		for (i = 0; i<udp_len; i+=4)
		{
			uint32_t data = *(uint32_t*)(buf+UDP_DATA_P+i);
			FLASH_ProgramWord(SN_START_PAGE + i + active_code_length, data);
		}
		for (i = 0; i < sizeof(rsa_buf); i += 4)
		{
			uint32_t write_data = *(uint32_t*)(rsa_buf+i);
			FLASH_ProgramWord(SN_START_PAGE+1024+i, write_data);
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

#define IAP_STATE_INIT 0x00
#define IAP_STATE_ERR  0x01
#define IAP_STATE_NODATA    0x05
#define IAP_STATE_ERASE_OK  0x12
#define IAP_STATE_WRITE_OK  0x13
#define IAP_STATE_WRITE_ERR  0x14
#define IAP_STATE_END  0x26

		if (memcmp(buf+UDP_DATA_P, "opt", 3) == 0)
		{
			if (iap_state == IAP_STATE_ERR)
			{
				iap_state = IAP_STATE_INIT;
				memcpy(buf+UDP_DATA_P, "Too Big!!", 9);

				make_udp_reply_with_data(buf, 9, 65518);
			}
			else if (iap_state == IAP_STATE_NODATA)
			{
				iap_state = IAP_STATE_INIT;
				memcpy(buf+UDP_DATA_P, "Not Data!", 9);

				make_udp_reply_with_data(buf, 9, 65518);
			}
			else if (iap_state == IAP_STATE_ERASE_OK)
			{
				memcpy(buf+UDP_DATA_P, "Flash_Erase_ok", 14);

				make_udp_reply_with_data(buf, 14, 65518);
			}
			else if (iap_state == IAP_STATE_WRITE_OK)
			{
				int next_point = GetCurrentPoint();
				memcpy(buf+UDP_DATA_P, "Flash write ok", 14);
				memcpy(buf+UDP_DATA_P+14, &next_point, 4);
				make_udp_reply_with_data(buf, 18, 65518);
			}
			else if (iap_state == IAP_STATE_WRITE_ERR)
			{
				int next_point = GetCurrentPoint();
				memcpy(buf+UDP_DATA_P, "Flash writeerr", 14);
				memcpy(buf+UDP_DATA_P+14, &next_point, 4);
				make_udp_reply_with_data(buf, 18, 65518);
			}
			else if (iap_state == IAP_STATE_END)
			{
				FLASH_Status FLASHStatus;
				FLASHStatus = FLASH_ErasePage(iap_ip_address);
				if (FLASHStatus == FLASH_COMPLETE)
				{
					memcpy(buf+UDP_DATA_P, "I will jump ok", 14);
					make_udp_reply_with_data(buf, 14, 65518);
					NVIC_SystemReset();
				}
				else
				{
					int next_point = GetCurrentPoint();
					memcpy(buf+UDP_DATA_P, "Flash writeerr", 14);
					memcpy(buf+UDP_DATA_P+14, &next_point, 4);
					make_udp_reply_with_data(buf, 18, 65518);
				}
			}
		}
		else if (memcmp(buf+UDP_DATA_P, "err", 3) == 0)
		{
			iap_state = IAP_STATE_INIT;
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

				if (iap_state == IAP_STATE_INIT) // IAP_STATE_INIT || IAP_STATE_ERR || IAP_STATE_WRITE_OK
				{
					if (memcmp(buf+UDP_DATA_P, "iap_start", 9) == 0)
					{
						make_udp_reply_with_data(buf, payloadlen, 65518);
						
						memcpy(package_size.data_8, buf+UDP_DATA_P+9, 4);
						flash_length = package_size.data_32;
						if (package_size.data_32 > 228*1024)//51200
						{
							//too big
							iap_state = IAP_STATE_ERR;
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
							iap_state = IAP_STATE_ERASE_OK;
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
				else if (iap_state == 0x10) // IAP_STATE_ERASE_OK || IAP_STATE_WRITE_OK || IAP_STATE_WRITE_ERR
				{
					uint32_t RamSource;
					make_udp_reply_with_data(buf, payloadlen, 65518);
					if (memcmp(buf+UDP_DATA_P, "iap_data:", 9) == 0)
					{
						memcpy(package_size.data_8, buf+UDP_DATA_P+9, 4);
						iap_state = IAP_STATE_WRITE_OK;
						RamSource = (uint32_t)(buf + UDP_DATA_P + 13);

						memcpy(last_1k_cache+last_1k_cache_size, (char*)RamSource, package_size.data_32);
						last_1k_cache_size += package_size.data_32;

						if ((last_1k_cache_size == 2048) || 
							(FlashDestination+last_1k_cache_size) >= (ApplicationAddress + flash_length))
						{
							int last_FlashDestination = FlashDestination;
							// 增加擦除的流程
							FLASH_Unlock();
							FLASH_ErasePage(FlashDestination);
							
							RamSource = (uint32_t)(&last_1k_cache[0]);

							for (EraseCounter = 0; 
								EraseCounter < last_1k_cache_size && FlashDestination <  ApplicationAddress + flash_length;
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
									iap_state = IAP_STATE_WRITE_ERR;
									FlashDestination = last_FlashDestination;
									break;
								}
								FlashDestination += 4;
								RamSource += 4;
							}
							last_1k_cache_size = 0;
						}
						else if (last_1k_cache_size == 1024)
						{
						}
						else
						{
							// 
							last_1k_cache_size += 1;
						}
					}
					else if (memcmp(buf+UDP_DATA_P, "iap_end", 7) == 0)
					{
						iap_state = IAP_STATE_END;
					}
					else
					{
						//write flash ok;
						iap_state = IAP_STATE_NODATA;
					}
				}
				else
				{
					make_udp_reply_with_data(buf, payloadlen, 65518);
					iap_state = IAP_STATE_INIT;
				}
			}
		}
	}
	return;
}
