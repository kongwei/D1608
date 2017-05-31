#include "ENC28J60.h"
#include "stm32f10x.h"
#include "SPI.H"
#include "stm32f10x_conf.h"
#include "stm32f10x_tim.h"
#include "simple_server.h"
#include "ip_arp_udp_tcp.h"
#include <absacc.h>

const char MyText[] __at (0x08001F00) = __DATE__" "__TIME__; 

//unsigned char myip[4];// = {192, 168, 1, 15};
unsigned long int iap_ip_address = 0x0803E000;
Flash_Data myip;

void GPIO_Configuration(void);
GPIO_InitTypeDef GPIO_InitStructure;

unsigned char mymac[6] = {0x00, 0x04, 0xa3, 0x11, 0x01, 0x51};

int main(void)
{
	pFunction Jump_To_Application;
	uint32_t JumpAddress;
	uint32_t tmpreg;

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
		//跳转至work代码
		JumpAddress = *(__IO uint32_t*) (ApplicationAddress + 4);
		Jump_To_Application = (pFunction) JumpAddress;

		//初始化用户程序的堆栈指针
		__set_MSP(*(__IO uint32_t*) ApplicationAddress);
		Jump_To_Application();
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
		u32 CpuID[3];
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
| IAP         |6k
+-------------+     0x08001800
| SYSTEM DATA |10k
+-------------+     0x08004000
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
|             |     0x08010000
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
+-------------+     0x08020000
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
|             |     0x08030000
|             |
|             |
|             |
|             |
|             |
|             |
|             |
|             |
+-------------+     0x08039000
| LOG         |
|             |
|             |
|             |
+-------------+     0x0803E000
|             |
+-------------+     0x08040000
*/
