# SM3 的长度扩展攻击实验报告
## 1 实验目标
类比哈希函数 MD 结构的长度扩展攻击，对 SM3 算法加密的消息进行攻击。  
由于原始消息 $m$ 中固定位置通常存在需要服务端验证的密钥信息，攻击者无法得知密钥信息的内容，因此若需要成功伪造消息 $m'$ 与其哈希值，长度扩展攻击是一个好的对策。
## 2 SM3 算法原理
SM3 算法对长度为 $l (l<2^{64})$ 比特的消息 $m$ 经填充和压缩迭代生成长 $256$ 比特的杂凑值。  
主要步骤分为：消息填充、消息扩展、迭代压缩、输出结果 四个步骤。经多轮迭代压缩后输出 256 位（32 字节）的数值。
### 2.1 消息填充
SM3 算法将消息 $m$ 分为若干组，每组长 512 位（64 字节）。  
消息的填充长度为 $[\ 1,512\ ]$：  
 - 若消息长度 $l\equiv447\ mod\ 512$ 仅需对消息填充 1 比特 “$1$” 及 64 比特 $l$；  
 - 若消息长度 $l\equiv448\ mod\ 512$ 仅需对消息填充 64 比特 $l$；  
 - 若消息长度 $l\equiv0\ mod\ 512$ 则需要将消息的填充部分放入新一组。  
<br>

**消息填充规则**：  
已知消息 $m$ 长 $l$ 比特，若 $l$ 为 512 的整数倍则无需填充。若不是，则填充步骤如下：
 - 在 $m$ 末尾补充 1 比特的字符 “1”。
 - 填充 $k$ 比特“0”，其中 $k$ 是满足 $k≡(512-64)\ mod\ 512$ 的最小非负整数。
 - 添加一个 64 比特消息 $m$ 的长度 l，高位补 0。
### 2.2 消息扩展
单位换算规则：1 消息字= 32 位= 8 个 16 进制数字= 4 字节。  
显然，消息填充步骤产生的每一组 512 比特消息= 16 个消息字 = 64 字节，消息扩展步骤将每 16 个消息字扩展出 116 个消息字，最终得到 132 个消息字。  
得到的 132 个消息字中，前 68 个消息字作为 $W_{0},W_{1},…,W_{67}$，后 64 个消息字作为 $W_{0}',W_{1}',…,W_{63}'$。因此，每组消息可扩展为 $W_{0},W_{1},…,W_{67},W_{0}',W_{1}',…,W_{63}'$。  
<br>

**消息扩展规则**：  
 - 将消息分组 $B^{(i)}$ 划分为 16 个字：$W_{0},W_{1},…,W_{15}$。
 - 生成第 17 至 68 个消息字（$j\in16\rightarrow 68$）：  
$W_{j}\leftarrow P_{1}(W_{j-16}\oplus W_{j-9}\oplus(W_{j-3}\lll15))\oplus(W_{j-13}\lll7)\oplus W_{j-6}$  
其中，$P_{1}(X)=X\oplus(X\lll15)\oplus(X\lll23)$\lll$ 表示循环左移。
 - 生成第 69 至 132 个（后 64 个）消息字（$j\in 0\rightarrow 63$）：  
$W_{j}'=W_{j}\oplus W_{j+4}$  

**伪码表示**：  
将消息分组 $B^{(i)}$ 按以下方法扩展生成 132 个字 $W_{0},W_{1},...,W_{67},W_{0}',W_{1}',...,W_{63}'$，用于压缩函数 $CF$：  
a) 将消息分组 $B^{(i)}$ 划分为 16 个字 $W_{0},W_{1},...,W_{15}$  
b) FOR $j=16$ TO $67$  
&emsp;&emsp;$W_{j}\leftarrow P_{1}(W_{j-16}\oplus W_{j-9}\oplus(W_{j-3}\lll15))\oplus (W_{j-13}\lll7)\oplus W_{j-6}$  
&emsp;ENDFOR  
c) FOR $j=0$ TO $63$  
&emsp;&emsp;$W_{j}'=W_{j}\oplus W_{j+4}$  
&emsp;ENDFOR
### 2.3 迭代压缩
初始 IV 向量分别置于 A,B,C,D,E,F,G 8 个字寄存器中，每个字寄存器存储 32 位变量。具体数值见参考文献[^1]。  
每计算一次压缩函数都将 8 个字寄存器中的向量进行 64 轮迭代，每轮分别使用前 68 个消息字中的一个 $W_{j}$ 与后 64 个消息字中的 $W_{j}'$ 计算。64 轮迭代结束后将最后 8 个字寄存器中的向量与初始 IV 异或，得到本次压缩函数计算的输出，该输出作为下一次调用压缩函数时的初值。  
每一次计算压缩函数依次使用一个消息分组。直至所有消息分组全部参与计算，输出的压缩函数结果即为最终杂凑值。  

**压缩函数计算**：  
<div align=center>
<img src="https://github.com/GuanCZang/Innovation_and_Entrepreneurship_Practice/blob/LengthExtensionAttackForSM3/SM3CompressionFunction.png" width="500" />
</div>
<br>

**伪码表示**：  
令 $A,B,C,D,E,F,G,H$ 为字寄存器，$SS1,SS2,TT1,TT2$ 为中间变量，压缩函数 $V^{i+1}=CF(V^{(i)},B^{(i)}), 0\leq i\leq n-1$。计算过程描述如下：
$ABCDEFGH\leftarrow V^{(i)}$  
FOR $j=0$ TO $63$  
&emsp;$SS1\leftarrow((A\lll12)+E+(T_{j}\lll j))\lll 7$  
&emsp;$SS2\leftarrow SS1\oplus(A\lll12)$  
&emsp;$TT1\leftarrow FF_{j}(A,B,C)+D+SS2+W_{j}'$  
&emsp;$TT2\leftarrow GG_{j}(E,F,G)+H+SS1+W_{J}$  
&emsp;$D\leftarrow C$  
&emsp;$C\leftarrow B\lll9$  
&emsp;$B\leftarrow A$  
&emsp;$A\leftarrow TT1$  
&emsp;$H\leftarrow G$  
&emsp;$G\leftarrow F\lll19$  
&emsp;$F\leftarrow E$  
&emsp;$E\leftarrow P_{0}(TT2)$  
ENDFOR  
$V^{(i+1)}\leftarrow ABCDEFGH\oplus V^{(i)}$  
其中，$FF_{j}$ 为 $FF$ 函数，$GG_{j}$ 为 $GG$ 函数；字的存储为大端（big-endian）格式。  
### 2.4 输出结果
将最后一轮压缩函数得到的 $A,B,C,D,E,F,G,H$ 八个向量拼接，输出的结果即为 SM3 算法的最终输出。  

**伪码表示**：  
$A.B.C.D.E.F.G.H\leftarrow V^{(n)}$  
输出 256 比特的杂凑值 $y=ABCDEFGH$
## 3 攻击思路：
1. 随机生成一串消息 $m$ 作为原始消息（$|m|=l$），长度 $l$ 不限，经 SM3 加密后得到 8 个向量组成的 $H_{1}$。
2. 生成任意一串附加消息 $(append||padding')$。  
$append$ 部分为攻击者需要加入的新消息；$padding'$ 部分包括 1 比特 “$1$”、满足 $(k+|append|+1\equiv448\ mod\ 512)$ 的 $k$ 比特 $0$、以及 $64$ 比特 $\lceil (l-448)/512\rceil+1+|append|$（原始消息长度+原始消息填充长度+攻击者加入的新消息长度）。  
以 $H_{1}$ 的 8 个向量值作为初始值，对 $(append||padding')$ 进行消息扩展与压缩函数计算，得到 $H_{2}$。
4. 输出伪造成功的新消息 $m'=m||padding||append$ 及其 SM3 值 $H_{2}$。其中 $padding$ 为原始消息经消息填充后增加的部分。
## 4 实现过程
```c
```
## 5 运行结果截图

[^1]:[SM3密码杂凑算法-国家密码管理局-2010.12](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf)

