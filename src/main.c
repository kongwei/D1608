#include "ENC28J60.h"
#include "stm32f10x.h"
#include "SPI.H"
#include "stm32f10x_conf.h"
#include "stm32f10x_tim.h"
#include "simple_server.h"
#include "ip_arp_udp_tcp.h"
#include <md5.h>
#include <absacc.h>
#include <string.h>
#include <stdio.h>

const char start_key[30] __at (0x8002800) = "D2E89E2C768929EB28829DD438BE"; 

// 重要：app的校验码位置
const int app_key_address = 0x8012300;

extern char MyText[]; 

void CheckStart()
{
	unsigned char decrypt[16] = {0};
	char decrypt_string[40];
	MD5_CTX md5;

	MD5Init(&md5);
	MD5Update(&md5, (unsigned char*)0x8000000, 0x2000);
	MD5Final(&md5,decrypt);

	sprintf(decrypt_string, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", 
		decrypt[0],decrypt[1],decrypt[2],decrypt[3],decrypt[4], decrypt[6],decrypt[7],
		decrypt[8], decrypt[10],decrypt[11],decrypt[12],decrypt[13],decrypt[14],decrypt[15]);
	if (strcmp(decrypt_string, start_key) != 0)
	{
		// fault
		while(1);
	}
}
// 校验app程序
int CheckApp()
{
	unsigned char decrypt[16];
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, (unsigned char*)ApplicationAddress, app_key_address-ApplicationAddress);
	MD5Update(&md5, (unsigned char*)app_key_address+16, ApplicationAddress+0x1E000-(app_key_address+16));
	MD5Final(&md5,decrypt);

	// 比较
	return (memcmp((unsigned char*)app_key_address, decrypt, 16) == 0);
}

//unsigned char myip[4];// = {192, 168, 1, 15};
unsigned long int iap_ip_address = 0x0803E000;
Flash_Data myip;

void GPIO_Configuration(void);
GPIO_InitTypeDef GPIO_InitStructure;

unsigned char mymac[6] = {0x00, 0x04, 0xa3, 0x11, 0x01, 0x51};

u32 CpuID[3];

int main(void)
{
	pFunction Jump_To_Application;
	uint32_t JumpAddress;
	uint32_t tmpreg;

	CheckStart();

	NVIC_SetVectorTable(NVIC_VectTab_FLASH, 0x0000);
	SystemInit();

	/* GPIO管脚初始化 */
	GPIO_Configuration();

	RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;

	// AFIO->MAPR 的处理
	tmpreg = AFIO->MAPR;
	tmpreg |= AFIO_MAPR_SWJ_CFG_JTAGDISABLE;
	//tmpreg &= ~AFIO_MAPR_USART1_REMAP;
	tmpreg |=  AFIO_MAPR_USART1_REMAP;
	AFIO->MAPR = tmpreg;

	if ((*(__IO uint32_t*)iap_ip_address != 0x55aa4774)
		&& ((*(__IO uint32_t*)ApplicationAddress) & 0x2FFE0000 ) == 0x20000000)
	{
		if (CheckApp())
		{
			//跳转至work代码
			JumpAddress = *(__IO uint32_t*) (ApplicationAddress + 4);
			Jump_To_Application = (pFunction) JumpAddress;

			//初始化用户程序的堆栈指针
			__set_MSP(*(__IO uint32_t*) ApplicationAddress);
			Jump_To_Application();
		}
	}

	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_8;	    
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;  
	GPIO_Init(GPIOA, &GPIO_InitStructure);
	GPIO_SetBits(GPIOA, GPIO_Pin_8);

	/*SPI1接口初始化*/
	SPI1_Init();
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM2, ENABLE); 

	FLASH_Unlock();
	if (*(__IO uint32_t*)iap_ip_address == 0x55aa4774 )
	{
		myip.data_32 = *(__IO uint32_t*)(iap_ip_address + 4);
	}

	if (myip.data_32 == 0)
	{
		myip.data_8[0] = 10;
		myip.data_8[1] = 3;
		myip.data_8[2] = 1;
		myip.data_8[3] = 125;
	}

	{
		// 00,04,a3为MICROCHIP注册的MAC地址：
		// http://www.microchip.com/forums/m147413-print.aspx

		//获取CPU唯一ID
		CpuID[0]=*(vu32*)(0x1ffff7e8);
		CpuID[1]=*(vu32*)(0x1ffff7ec);
		CpuID[2]=*(vu32*)(0x1ffff7f0);
		
		mymac[3] = CpuID[0]&0xFF;
		mymac[4] = CpuID[1]&0xFF;
		mymac[5] = CpuID[2]&0xFF;

// 		mymac[3] = myip.data_8[0] ^ myip.data_8[1] ^ 0x55;
// 		mymac[4] = myip.data_8[2] ^ myip.data_8[3] ^ 0x47;
// 		mymac[5] = myip.data_8[2] ^ 0x74 + myip.data_8[3] ^ 0x3c;

		/*初始化ENC28J60*/
		enc28j60Init(mymac);

		init_ip_arp_udp_tcp(mymac, myip.data_8, 0);

		/*ENC28J60初始化以及Server程序*/
		while(1)
		{	 
			simple_server_start();
		}
	}
}

/*GPIO接口初始化*/
void GPIO_Configuration(void)
{
	//使用到的资源时钟使能
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_USART1|RCC_APB2Periph_GPIOA|RCC_APB2Periph_GPIOB
		|RCC_APB2Periph_GPIOC|RCC_APB2Periph_GPIOF, ENABLE);

// 	/*LED灯初始化*/
// 	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6|GPIO_Pin_7|GPIO_Pin_8|GPIO_Pin_9;	//DS1--4 
// 	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
// 	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
// 	GPIO_Init(GPIOF, &GPIO_InitStructure);

	/*ENC28J60的INT中断输入初始化*/
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_2;	        
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IPD;   
	GPIO_Init(GPIOC, &GPIO_InitStructure);
}

/******************* (C) COPYRIGHT 2010 STMicroelectronics *****END OF FILE****/



/*
flash使用情况

+-------------+     0x08000000
| IAP         |4k
+-------------+     0x08003000
| APP         |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
+-------------+     0x08021000
| PRESET      |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
+-------------+     0x08030000
|             |
|             |
|             |
|             |
|             |
+-------------+     0x08038800
| IAP         |
|             |
+-------------+     0x08039000
| LOG         |
|             |
|             |
|             |
+-------------+     0x0803E000
|             |
|             |
+-------------+     0x0803E800
| 工厂配置    |
|             |
|             |
+-------------+     0x08040000
*/
