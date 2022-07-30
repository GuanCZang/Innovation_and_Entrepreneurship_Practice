/************************************************************************
 File name: SM3.c
 Version: SM3_V1.1
 Date: Sep 18,2016
 Description: to calculate a hash message from a given message
 Function List:
 1.SM3_256			//calls SM3_init, SM3_process and SM3_done to calculate hash value
 2.SM3_init			//init the SM3 state
 3.SM3_process		//compress the the first len/64 blocks of the message
 4.SM3_done			//compress the rest message and output the hash value
 5.SM3_compress		//called by SM3_process and SM3_done, compress a single block of message
 6.BiToW			//called by SM3_compress,to calculate W from Bi
 7.WToW1			//called by SM3_compress, calculate W1 from W
 8.CF				//called by SM3_compress, to calculate CF function.
 9.BigEndian		//called by SM3_compress and SM3_done.GM/T 0004-2012 requires to use big-endian.
					//if CPU uses little-endian, BigEndian function is a necessary call to change the
					//little-endian format into big-endian format.
 10.SM3_SelfTest	//test whether the SM3 calculation is correct by comparing the hash result with the standard result
 History:
 1. Date: Sep 18,2016
	Author: Mao Yingying, Huo Lili
	Modification: 1)add notes to all the functions
				  2)add SM3_SelfTest function
**************************************************************************/
#include "SM3.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/****************************************************************
 Function:		BiToW
 Description:	calculate W from Bi 由第i个消息分组计算W
 Calls:
 Called By:		SM3_compress
 Input:			Bi[16]	//a block of a message
 Output:		W[64]
 Return:		null
 Others:
****************************************************************/
void BiToW(unsigned int Bi[], unsigned int W[])
{
	int i;
	unsigned int tmp;

	for (i = 0; i <= 15; i++)
	{
		W[i] = Bi[i];
	}
	for (i = 16; i <= 67; i++)
	{
		tmp = W[i - 16]^W[i - 9]^SM3_rotl32(W[i - 3], 15);
		W[i] = SM3_p1(tmp)^(SM3_rotl32(W[i - 13], 7))^W[i - 6];
	}
}
/*****************************************************************
 Function: WToW1
 Description: calculate W1 from W 由W计算W'
 Calls:
 Called By: SM3_compress
 Input: W[64]
 Output: W1[64]
 Return: null
 Others:
*****************************************************************/
void WToW1(unsigned int W[], unsigned int W1[])
{
	int i;
	for (i = 0; i <= 63; i++)
	{
		W1[i] = W[i] ^ W[i + 4];
	}
}
/******************************************************************
 Function: CF 压缩函数
 Description: calculate the CF compress function and update V
 Calls:
 Called By: SM3_compress
 Input: W[64]
 W1[64]
 V[8]
 Output: V[8]
 Return: null
 Others:
********************************************************************/
void CF(unsigned int W[], unsigned int W1[], unsigned int V[])
{
	unsigned int SS1;
	unsigned int SS2;
	unsigned int TT1;
	unsigned int TT2;
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int T = SM3_T1;
	unsigned int FF;
	unsigned int GG;
	int j;

	//reg init,set ABCDEFGH=V0
	A = V[0];
	B = V[1];
	C = V[2];
	D = V[3];
	E = V[4];
	F = V[5];
	G = V[6];
	H = V[7];

	for (j = 0; j <= 63; j++)
	{
		//SS1
		if (j == 0)
		{
			T = SM3_T1;
		}
		else if (j == 16)
		{
			T = SM3_rotl32(SM3_T2, 16);
		}
		else
		{
			T = SM3_rotl32(T, 1);
		}
		SS1 = SM3_rotl32((SM3_rotl32(A, 12) + E + T), 7);

		//SS2
		SS2 = SS1 ^ SM3_rotl32(A, 12);

		//TT1
		if (j <= 15)
		{
			FF = SM3_ff0(A, B, C);
		}
		else
		{
			FF = SM3_ff1(A, B, C);
		}
		TT1 = FF + D + SS2 + *W1;
		W1++;

		//TT2
		if (j <= 15)
		{
			GG = SM3_gg0(E, F, G);
		}
		else
		{
			GG = SM3_gg1(E, F, G);
		}
		TT2 = GG + H + SS1 + *W;
		W++;

		//D
		D = C;

		//C
		C = SM3_rotl32(B, 9);

		//B
		B = A;

		//A
		A = TT1;

		//H
		H = G;

		//G
		G = SM3_rotl32(F, 19);

		//F
		F = E;

		//E
		E = SM3_p0(TT2);
	}

	//update V
	V[0] = A ^ V[0];
	V[1] = B ^ V[1];
	V[2] = C ^ V[2];
	V[3] = D ^ V[3];
	V[4] = E ^ V[4];
	V[5] = F ^ V[5];
	V[6] = G ^ V[6];
	V[7] = H ^ V[7];
}
/******************************************************************************
 Function: BigEndian 小端数据转大端存储
 Description: U32 endian converse.GM/T 0004-2012 requires to use big-endian.
 if CPU uses little-endian, BigEndian function is a necessary
 call to change the little-endian format into big-endian format.
 Calls:
 Called By: SM3_compress, SM3_done
 Input: src[bytelen] 原比特长度
		bytelen
 Output: des[bytelen] 目标比特长度
 Return: null
 Others: src and des could implies the same address
*******************************************************************************/
void BigEndian(unsigned char src[], unsigned int bytelen, unsigned char des[])
{
	unsigned char tmp = 0;
	unsigned int i = 0;

	for (i = 0; i < bytelen / 4; i++)	//第0,3位字节内容交换；第1,2位字节内容交换
	{
		tmp = des[4 * i];
		des[4 * i] = src[4 * i + 3];
		src[4 * i + 3] = tmp;

		tmp = des[4 * i + 1];
		des[4 * i + 1] = src[4 * i + 2];
		des[4 * i + 2] = tmp;
	}
}
/******************************************************************************
 Function: SM3_init
 Description: initiate SM3 state 初始化SM3
 Calls:
 Called By: SM3_256
 Input: SM3_STATE *md
 Output: SM3_STATE *md
 Return: null
 Others:
*******************************************************************************/
void SM3_init(SM3_STATE* md) //md为SM_STATE结构体的指针
{
	md->curlen = md->length = 0;	// 结构体中进行的分组长度与总长度初始化为0
	md->state[0] = SM3_IVA;			// 结构体中的状态[0]-[7]设置为初始向量IV
	md->state[1] = SM3_IVB;
	md->state[2] = SM3_IVC;
	md->state[3] = SM3_IVD;
	md->state[4] = SM3_IVE;
	md->state[5] = SM3_IVF;
	md->state[6] = SM3_IVG;
	md->state[7] = SM3_IVH;
}
/******************************************************************************
 Function: SM3_compress
 Description: compress a single block of message 压缩函数
 Calls: BigEndian
 BiToW
 WToW1
 CF
 Called By: SM3_256
 Input: SM3_STATE *md
 Output: SM3_STATE *md
 Return: null
 Others:
*******************************************************************************/
void SM3_compress(SM3_STATE* md)
{
	unsigned int W[68];
	unsigned int W1[64];

	//if CPU uses little-endian, BigEndian function is a necessary call
	BigEndian(md->buf, 64, md->buf);

	BiToW((unsigned int*)md->buf, W);	// 生成W
	WToW1(W, W1);						// 生成W'
	CF(W, W1, md->state);				// 计算压缩函数
}
/******************************************************************************
 Function: SM3_process
 Description: compress the first (len/64) blocks of message
 Calls: SM3_compress
 Called By: SM3_256
 Input: SM3_STATE *md
		unsigned char buf[len] //the input message
		int len //bytelen of message
 Output: SM3_STATE *md
 Return: null
 Others:
*******************************************************************************/
void SM3_process(SM3_STATE* md, unsigned char* buf, int len)
{
	while (len--)	//len为字节长度的消息（原or附加），先取值后减，当len为0时退出循环。随输入存入数组的进行而减少
	{
		/* copy byte */
		md->buf[md->curlen] = *buf++;	//	buf地址向后移动8比特=1字节，对应的元素赋给buf数组的当前长度下标对应位置数据。即将输入输入消息逐一填入当前分组的数组
		md->curlen++;					// 当前长度+1

		/* is 64 bytes full? */
		if (md->curlen == 64)			// 若输入的消息刚好填满当前消息块则直接进入压缩函数
		{
			SM3_compress(md);
			md->length += 512;			// 当前已有消息长度加一个分组
			md->curlen = 0;				// 分组当前长度清空
		}
	}
}
/******************************************************************************
 Function: SM3_done
 Description: compress the rest message that the SM3_process has left behind 压缩SM3_process留下的其余消息
 Calls: SM3_compress
 Called By: SM3_256
 Input: SM3_STATE *md
 Output: unsigned char *hash
 Return: null
 Others:
*******************************************************************************/
void SM3_done(SM3_STATE* md, unsigned char hash[])
{
	int i;
	unsigned char tmp = 0;

	/* increase the bit length of the message */	//消息填充
	md->length += md->curlen << 3;					//当前原始消息总长度

	/* append the '1' bit */						//填充1
	md->buf[md->curlen] = 0x80;
	md->curlen++;

	/* if the length is currently above 56 bytes, appends zeros till
	it reaches 64 bytes, compress the current block, creat a new
	block by appending zeros and length,and then compress it
	*/
	if (md->curlen > 56)							// 将当前块的剩下部分填充0
	{
		for (; md->curlen < 64;)
		{
			md->buf[md->curlen] = 0;
			md->curlen++;
		}
		SM3_compress(md);
		md->curlen = 0;
	}

	/* if the length is less than 56 bytes, pad upto 56 bytes of zeroes */
	for (; md->curlen < 56;)						// 保留填充长度的部分，剩下填充0
	{
		md->buf[md->curlen] = 0;
		md->curlen++;
	}

	/* since all messages are under 2^32 bits we mark the top bits zero */ //？？？？？？？？？？？？？？？？？？？？？？？？？？？
	for (i = 56; i < 60; i++)						// 32bit=4byte=ffffffff=1个消息字
	{
		md->buf[i] = 0;
	}

	/* append length */								// 长度填充
	md->buf[63] = md->length & 0xff;				// 取最低八位存入buf[63]
	md->buf[62] = (md->length >> 8) & 0xff;			// 往后高八位存入，下同
	md->buf[61] = (md->length >> 16) & 0xff;
	md->buf[60] = (md->length >> 24) & 0xff;

	SM3_compress(md);

	/* copy output */
	memcpy(hash, md->state, SM3_len / 8);	// 将md->state复制SM3_len/8字节到hash
	BigEndian(hash, SM3_len / 8, hash);//if CPU uses little-endian, BigEndian function is a necessary call
}
/******************************************************************************
 Function: SM3_256
 Description: calculate a hash value from a given message
 Calls: SM3_init
 SM3_process
 SM3_done
 Called By:
 Input: unsigned char buf[len] //the input message
 int len //bytelen of the message
 Output: unsigned char hash[32]
 Return: null
 Others:
*******************************************************************************/
void SM3_256(unsigned char buf[], int len, unsigned char hash[])	//消息填充（消息输入/消息长度/消息哈希）
{
	SM3_STATE md;
	SM3_init(&md);
	SM3_process(&md, buf, len);
	SM3_done(&md, hash);
}
/******************************************************************************
 Function: SM3_SelfTest
 Description: test whether the SM3 calculation is correct by comparing
 the hash result with the standard result
 Calls: SM3_256
 Called By:
 Input: null
 Output: null
 Return: 0 //the SM3 operation is correct
 1 //the sm3 operation is wrong
 Others:
*******************************************************************************/
//int SM3_SelfTest()
//{
//	unsigned int i = 0, a = 1, b = 1;
//	unsigned char Msg1[3] = { 0x61,0x62,0x63 };
//	int MsgLen1 = 3;
//	unsigned char MsgHash1[32] = { 0 };
//	unsigned char StdHash1[32] = 
//	{ 0x66,0xC7,0xF0,0xF4,0x62,0xEE,0xED,0xD9,0xD1,0xF2,0xD4,0x6B,0xDC,0x10,0xE4,0xE2,
//	  0x41,0x67,0xC4,0x87,0x5C,0xF2,0xF7,0xA2,0x29,0x7D,0xA0,0x2B,0x8F,0x4B,0xA8,0xE0 };
//	unsigned char Msg2[64] = 
//	{ 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
//	  0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
//	  0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
//	  0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64 };
//	int MsgLen2 = 64;
//	unsigned char MsgHash2[32] = { 0 };
//	unsigned char StdHash2[32] = 
//	{ 0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
//	  0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32 };
//	SM3_256(Msg1, MsgLen1, MsgHash1);
//	SM3_256(Msg2, MsgLen2, MsgHash2);
//
//	a = memcmp(MsgHash1, StdHash1, SM3_len / 8);
//	b = memcmp(MsgHash2, StdHash2, SM3_len / 8);
//
//	if ((a == 0) && (b == 0))
//	{
//		return 0;
//	}
//	else
//	{
//		return 1;
//	}
//}

/************************************************************************************
以下为长度扩展攻击部分增加代码
*************************************************************************************/
SM3_STATE SS;												//用于继承H_1
void SM3_Append_init(SM3_APPEND_STATE* mdA) //mdA为SM_APPEND_STATE结构体的指针
{
	mdA->curlen = 0;	// 结构体中进行的分组长度初始化为0
	mdA->length = (unsigned int)((ceil(SS.length) - 448 / 512) + 1) * 512;			//l+append
	// IV=H_1
	//printf("新消息初始向量：");
	//for (int i = 0; i < 8; i++)
	//{
	//	mdA->state[i] = SS.state[i];												//！！！【SS.state无法复制出数组，原因未知】
	//	printf("%x\ ", mdA->state[i]);
	//}
	//printf("\n");

	//不需要知道原始消息
	//for (int i = 0; i < 64; i++)
	//{
	//	mdA->buf[i] = SS.buf[i];							//原始消息m及其append
	//}
}
void SM3_Append_process(SM3_APPEND_STATE* mdA, unsigned char* bufA, int len)
{
	while (len--)	//len为字节长度的消息（原or附加），先取值后减，当len为0时退出循环。随输入存入数组的进行而减少
	{
		/* copy byte */
		mdA->buf[mdA->curlen] = *bufA++; //buf地址向后移动8比特=1字节，对应的元素赋给buf数组的当前长度下标对应位置数据。即将输入输入消息逐一填入当前分组的数组
		mdA->curlen++;					// 当前长度+1

		/* is 64 bytes full? */
		if (mdA->curlen == 64)			// 若输入的消息刚好填满当前消息块则直接进入压缩函数
		{
			SM3_compress(mdA);
			mdA->length += 512;			// 当前已有消息长度加一个分组
			mdA->curlen = 0;				// 分组当前长度清空
		}
	}
}
void SM3_Append_done(SM3_APPEND_STATE* mdA, unsigned char hash[])
{
	int i;
	unsigned char tmp = 0;

	/* increase the bit length of the message */								//消息填充
	double Dlength = mdA->length;
	mdA->length += mdA->curlen << 3;											//当前原始消息长度+原始消息填充长度+附加消息长度总长度后赋给消息总长并向左偏移三比特（单位由字节转为比特）

	/* append the '1' bit */													//填充1
	mdA->buf[mdA->curlen] = 0x80;
	mdA->curlen++;

	/* if the length is currently above 56 bytes, appends zeros till
	it reaches 64 bytes, compress the current block, creat a new
	block by appending zeros and length,and then compress it
	*/
	if (mdA->curlen > 56)							// 将当前块的剩下部分填充0
	{
		for (; mdA->curlen < 64;)
		{
			mdA->buf[mdA->curlen] = 0;
			mdA->curlen++;
		}
		SM3_compress(mdA);
		mdA->curlen = 0;
	}

	/* if the length is less than 56 bytes, pad upto 56 bytes of zeroes */
	for (; mdA->curlen < 56;)						// 保留填充长度的部分，剩下填充0
	{
		mdA->buf[mdA->curlen] = 0;
		mdA->curlen++;
	}

	///* since all messages are under 2^32 bits we mark the top bits zero */ //？？？？？？？？？？？？？？？？？？？？？？？？？？？
	//for (i = 56; i < 60; i++)						// 32bit=4byte=ffffffff=1个消息字
	//{
	//	mdA->buf[i] = 0;
	//}

	/* append length */								// 长度填充
	mdA->buf[63] = mdA->length & 0xff;				// 取最低八位存入buf[63]
	mdA->buf[62] = (mdA->length >> 8) & 0xff;			// 往后高八位存入，下同
	mdA->buf[61] = (mdA->length >> 16) & 0xff;
	mdA->buf[60] = (mdA->length >> 24) & 0xff;
	mdA->buf[59] = (mdA->length >> 32) & 0xff;
	mdA->buf[58] = (mdA->length >> 40) & 0xff;
	mdA->buf[57] = (mdA->length >> 48) & 0xff;
	mdA->buf[56] = (mdA->length >> 56) & 0xff;


	SM3_compress(mdA);

	/* copy output */
	memcpy(hash, mdA->state, SM3_len / 8);	// 将mdA->state复制SM3_len/8字节到hash
	BigEndian(hash, SM3_len / 8, hash);//if CPU uses little-endian, BigEndian function is a necessary call
}
void SM3_Append_256(unsigned char buf[], int len, unsigned char hash[])	//消息填充（消息输入/消息长度/消息哈希）
{
	SM3_APPEND_STATE mdA;
	SM3_Append_init(&mdA);
	SM3_Append_process(&mdA, buf, len);
	SM3_Append_done(&mdA, hash);
}


int main()
{
	unsigned char M[3] = { 97,98,99 };			//原始消息m
	int MLen = 3;								//|m|=3
	unsigned char MH1[32] = { 0 };				//初始化原始消息m的哈希函数H1
	SM3_256(M, MLen, MH1);						//计算原始消息的哈希函数H1

	printf("原始消息m：");
	for (int i = 0; i < 3; i++)
	{
		printf("%c", M[i]);
	}
	printf("\n");

	printf("\n原始消息哈希值：");
	for (int i = 0; i < 32; i++)
	{
		printf("%x", MH1[i]);
		if ((i + 1) % 4 == 0)
		{
			printf("\ ");
		}
	}
	printf("\n");

	// 伪造消息扩展攻击
	SM3_APPEND_STATE SAS;
	unsigned char Append[3] = { 'd','e','f' };	//附加消息append
	int AppendLen = 3;							//|append|=3
	unsigned char M_H2[32] = { 0 };				//新消息m'的哈希值
	//保留m+padding
	SM3_Append_256(Append, AppendLen, M_H2);

	//printf("新消息m：");						//原始消息敌手不知道
	//for (int i = 0; i < (sizeof(SAS.buf) / sizeof(SAS.buf[0])); i++)
	//{
	//	printf("%c", SAS.buf[i]);
	//}
	//for (int i = 0; i < 3; i++)
	//{
	//	printf("%c", Append[i]);
	//}
	printf("\n填充def后新消息哈希值：");
	for (int i = 0; i < 32; i++)
	{
		printf("%x", M_H2[i]);
		if ((i + 1) % 4 == 0)
		{
			printf("\ ");
		}
	}
	printf("\n");

}