# TCP/IP

## 第一章 概述

### 信息时代

- 21世纪的重要特征：数字化、网络化和信息化，它是以网络为核心的信息时代

- 三大类网络：将以下三种网络融合成一种网络的的思想是<font color='red'> **“三网融合”**</font>

  |                             名称                             |           描述           |
  | :----------------------------------------------------------: | :----------------------: |
  |                           电信网络                           | 提供电话、电报和传真服务 |
  |                         有线电视网络                         |  向用户传送各种电视节目  |
  | 计算机网络<font color='red'> **（发展最快并起到核心作用的网络）**</font> |   在计算机之间传输数据   |

- 现代互联网的特征：<font color='red'>**连通性、共享性**</font>

### 互联网概述

#### 互联网名词解释

- **因特网/互联网（Internet）**：**特指** Internet ，起源于美国，现已经发展成世界上最大的、覆盖最全球的计算机网络

- **互连网（internet/internetwork）**：泛指通过路由器把**网络互连**起来，这样就构成的一个范围更大的计算机网络，<font color='red'>**“网络的网络”**</font>
  - 网络互连计算机等终端设备，而互连网则将网络通过路由器连接起来

#### 互联网发展的三个阶段：

- 第一阶段：从单个网络 ARPANET 向互联网发展的过程
- 第二阶段：建成三级结构的互联网
- 第三阶段：形成全球范围的**多层次ISP结构**的互联网

|                  阶段                   |                   特征                    |
| :-------------------------------------: | :---------------------------------------: |
|  从单个网络 ARPANET 向互联网发展的过程  |            TCP/IP协议初步形成             |
|          建成三级结构的互联网           | 形成了主干网、地区网、校园/企业网三层结构 |
| 形成全球范围的**多层次ISP结构**的互联网 | ISP（Internet Service Provider） 首次出现 |

#### 互联网标准制定的三个阶段：

1. 互联网草案（Internet Draft）：有效期6个月，不是 RFC（Request For Comment） 文档
2. 建议标准（Proposed Standard）：这个阶段开始成为 RFC 文档
3. 互联网标准（Internet Standard）：成为正式标准，被分配一个编号 STDxx，一个标准能够关联多个 RFC 文档

### 互联网的组成

#### 互联网的组成部分：

- 边缘部分：由连接在互联网上的主机组成，供用户直接使用，用于通信和资源共享。主机又成为端系统
- 核心部分：由大量网络和连接这些网路的路由器组成，为边缘部分提供服务（连通性和交换）

#### 互联网的边缘部分：

- 端系统之间的通信方式有两种：
  - 客户/服务器方式（C/S方式）即 Client/Server 方式，简称 C/S 方式；
  - 对等方式（P2P方式）即 Peer to Peer 方式，简称 P2P 方式
- C/S方式：服务器和客户都指通信中所涉及的两个应用进程，客户-服务器方式所 **描述的是进程之间的服务与被服务关系**
  - 客户程序：被用户调用后，会主动向远程服务器发起通信；客户程序必须要指导服务器程序的地址
  - 服务器程序：专门用来提供服务的程序，**能够同时处理多个**远程或本地的客户请求。系统启动后**自动调用并且一直运行**，**被动等待**并接收来自各地的客户通信请求。服务器程序不需要知道客户程序的地址。
- P2P方式：指的是**对等连接**，不存在服务与被服务的关系，在运行时**不区分服务请求方和服务提供方**；
  - 只要两个主机都下载了对等连接软件，它们就可以进行平等的、对等连接通信
  - 双方都可以下载对方已经存储在硬盘中的共享文档
  - 对等连接中的双方既是服务器也是客户

#### 互联网的核心部分

- 链路速率区分：互联网的核心部分之间的路由器一般都用**高速链路相连接**；而网络边缘部分接入核心部分通常**链路速率相对较低**
- 路由器：
  - 网络核心部分是互联网中最复杂的部分，在网络核心部分起特殊作用的是路由器；
  - 路由器是实现分组交换的关键构建，其任务是转发收到的分组，这是网络核心部分最重要的功能

#### 分组交换和电路交换

- 电路交换：
  - 通信前<font color = 'red'>**（面向连接）**</font>：电路交换必须要建立连接，建立一条专用的物理通路（面向连接）
  - 通信时<font color = 'red'>**（独占资源）**</font>：主叫和被叫双方能相互通电话，且通话时通信资源不会被其他用户占用
  - 通信后<font color = 'red'>**（释放资源）**</font>：结束通信时释放刚刚使用的这条专用物理链路
  - 特点：电路交换 **始终占用** 端到端的通信资源
- 分组交换：
  - 特点：使用存储转发技术，把较长的报文分成较短的，长度固定的**数据段**，为每个数据段前面添加上**首部**构成**分组**（packet）
  - 优势：<font color = 'red'>**动态分配带宽；分组独立路由；非面向连接**</font>
    - **动态分配**传输带宽；
    - 每个分组**独立选择最合适的路由**；
    - **不建立连接**就能够向其他主机发送分组；
  - 缺点：<font color = 'red'>**排队时延；首部额外开销**</font>
    - 存储转发时排队会造成时延
    - 分组必须携带首部造成额外开销
  - 路由器的工作原理：（路由器输入输出口之间没有直接连线）
    - **存储分组**：收到分组后存入缓存
    - **查表转发**：根据首部的目的地址，查找转发表，找到对应端口将数据转发出去

#### 计算机网络的分类

- 从网络的作用范围来分类

  |              名称               |          简介          |
  | :-----------------------------: | :--------------------: |
  | 广域网 WAN（Wide Area Network） | 作用范围几十到几千公里 |
  |           城域网 MAN            |   作用距离为5-50公里   |
  |           局域网 LAN            |                        |
  |         个人区域网 PAN          |                        |

- 从网络的使用者来分类

  |  名称  |                简介                |
  | :----: | :--------------------------------: |
  | 公用网 | 按规定缴纳费用的人都可以使用的网络 |
  | 专用网 |  为特殊业务工作的需要而建造的网络  |

- 接入网的概念

  - 比较特殊的一类网络，用于将用户接入互联网
  - 既不属于互联网的核心部分，也不属于互联网的边缘部分
  - 接入网是用户端系统到互联网中第一个路由器（边缘路由器）之间的一种网络

#### 计算机网络的性能指标

