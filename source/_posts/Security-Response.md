---
title: Linux——安全事件应急响应（1）
tags: 信息安全
categories: 信息安全
description: 本文主要介绍了挖矿类的恶意程序如何排查清理。
keywords: #关键字
top_img: #顶部图
cover: #封面图
date: 2024-10-18 21:47:14
---

# 前言

- 没有任何人可以保证绝对的网络\信息安全，只有安全团队尽最大的保障能力做到相对安全；
- 若发生不可避免的安全事件，那么调查溯源、安全上报、事件取证甚至反向渗透就成了重中之重。
- 本系列文章将持续记录、分享自己学过、用过、见过的一些网络安全事件应急响应方法。没有任何装13卖弄的本意。
- 另外：**本系列文章中，所用到的一些方法、手段也并非本人原创**，若侵犯了原作者的相关权益，请及时与我联系，本人必将第一时间删除。

# 安全事件预警来源

## 安全事件预警大概有以下几种：

- 安全设备告警
	- 态势感知
		- 事件发生时间
		- 源目IP
		- 源目端口
		- 协议类型
		- 原始数据包
		- 返回数据包
	- 防火墙预警
		- 事件时间
		- 源目IP
		- 源目端口
		- 协议类型
		- 原始数据包
	- EDR
		- 事件时间
		- 攻击方式
		- 恶意文件
		- 源目主机（IP）
		- 源目端口
	- VPN（存在数据中心）
		- 登录时间
		- 源目IP
		- 是否发生暴力破解
- 流量监控设备告警
		- 流量态势图
		- 流量类型
		- 目的IP
		- 目的端口
		- 源IP
- 工作人员
		- 异常发现时间
		- 主机功能
		- 主机归属
		- 主机信息
			- 系统
			- 服务
			- 端口
- 上级\同级监管单位
	- 攻击事件通报
		- 被攻击资产
		- 攻击类型

> 不同的事件类型有着不同的方式/角度去解决问题，单次的安全事件可能包含多种类型的事件

# 事件响应前的准备

* 物理写保护U盘
* busybox    #集成工具，将Linux的部分工具进行了整合，节省了许多代码，不过部分工具的参数没有系统自带的多。
* 各种查杀工具    #根据业主环境可使用业主指定或安全响应人员信赖的。
* 纯净的Linux操作系统虚拟机 #Ubuntu、Centos、Debian、kali
* Linux克隆取证启动U盘
* 克隆取证数据存储硬盘    #最好是两个，可能需要送样本到监管部门，留下一个可由安全团队溯源研究。
* 响应报告一份    #Markdown格式最佳

# 挖矿事件应急响应

## **0x01_恶意程序判断**

- 根据内网dns服务器、dns防火墙、流量审计、态势感知等设备获取恶意程序或者恶意程序的md5
- 根据以下域名确认恶意程序类型
	- 绿盟威胁情报中心
	- Virustotal
	- 深信服威胁情报中心
	- 微步在线
	- venuseye
	- 安恒威胁情报中心
	- RedQueen安全智能服务平台
	- IBM X-Force Exchange
	- ThreatMiner

## **0x02_获取异常进程pid**

- CPU占用
	```BASH
	top -c -o %CPU
	```
	> - -c参数显示进程的命令行参数
	> - -p参数指定进程的pid

	```BASH
	ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%cpu | head -n 5
	```
	> cpu占用前5的进程信息

- 内存占用
	```BASH
		top -c -o %MEM
	```
> -c参数显示进程的命令行参数
> -p参数指定进程的pid

	```BASH
	ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%mem | head -n 5
	```
	> 内存占用前5的进程信息（若对恶意程序有猜测，可用grep命令过滤，验证猜测）

- 网络占用
  > 网络占用需要nethogs和jnettop这两款工具软件，并使用root权限之行
  > Debian｜Ubuntu｜Kali操作系统安装
  > ```BASH
  > sudo apt-get install nethogs
  > sudo apt-get install jnettop
  > ```
  > Centos|RHEL操作系统安装
  > ```BASH
  > sudo yum -y install epel-release
  > sudo yum -y install nethogs
  > sudo yun -y install jnettop
  > ```
  > 安装过程中若出现依赖问题，可使用-f参数修复安装。
  > 之后之行
  > ```BASH
 	sudo nethogs
 	sudo jnettop
 	```

## **0x03_定位恶意程序文件样本**

 经过以上步骤，基本上可以获取到异常进程pid或者相关的命令行命令

 - 根据进程名字或者部分字符串获取pid
	 ```BASH
	  pidof ‘name’
	  ps -aux | grep ‘name’
	  ps -ef | grep ‘name’ | grep -v grep | awk ‘{print $2}’
	  pgrep -f ‘name’
		```
 - 根据pid获取程序的详细信息
	 ```BASH
	 lsof -p pid
	 pwdx pid
	 ```
	 > pwdx——获取该pid的进程启动的时候的目录；**注意**，该命令打印出的结果**并不一定就是恶意程序的所在路径，只是启动恶意程序的路径；**（我个人将之称为触发路径，虽然不专业但是方便区分，就像linux中的启动器一样，我菜，勿喷）

	 ```BASH
	 cat /proc/pid/maps
	 ls -lah /proc/pid/exe
	 systemctl status pid
	 ```
	 > systemctl status pid ——获取该pid进程的详细status信息
	 > Ps：有些时候，无法通过ps，top等命令根据pid进行查询，可能是因为攻击者将/proc/pid/进行了隐藏，具体的方式应该是通过以下方式进行的隐藏pid**（切勿乱用，小心牢饭；Debian系列的测试成功，centos测试不成功）**
   > ```BASH
		  mkdir .hidden
		  mount -o bind .hidden /proc/PID
	  ```
	 > 若在实际环境中遇到被隐藏的pid可以使用 **cat /proc/$$/mountinfo** 来查看挂载信息

	- 根据pid查看由进程起的线程

	```BASH
	ps H -T -p pid
	ps -Lf pid
	```
	![ps -T -p pid](/img/post_img/241019/ps_pid.jpg)
	- 其中SPID就是线程ID，而CMD一栏则显示了线程名称

	```BASH
	top -H -p pid
	#-H选项可以显示线程

	htop
	#htop工具Linnx工具默认未安装，该命令做作用于top命令功能相同，不过显示的信息更为全面，可以更加直观的展示线程

	pstree -agplU
	#pstree命令，十分推荐；以树形式详细、全面的展示进程与线程之间的关系。

	```

## **0x04_确认恶意程序运行时间**

- 查看程序运行时间

	```BASH
	ps -eo pid,lstart,etime,cmd | grep <pid>
	```
	![ps_time](./img/post_img/241019/ps_time.jpg)

  > 表示pid为1292的进程是在2022年4月28日13:32:20被创建的。已经运行了30分零2秒，具体执行的命令行为 **/usr/sbin/sshd -D**

- 与找到的恶意文件创建时间进行对比

	```BASH
	stat xxx.sh
	```
	![ps_db](./img/post_img/241019/ps_db.jpg)

	```BASH
	ls -al xxx.sh
	```
	![ps_db2](./img/post_img/241019/ps_db2.jpg)

  > 该部分是为了验证定位到的文件是否为当前恶意程序的恶意文件，增加此对比，可能会发现一些之前没能发现蛛丝马迹

## **0x05_处理异常的进程**
- 恶意文件样本采样
	```BASH
		scp -P 4588 remote@RHOST_address:/file/to/patch/file /home/your/file/to/path
		#scp命令，-P指定ssh端口，从远程服务器（被攻击主机remote@RHOST_address）将恶意文件样本（file/to/patch/file）下载到本地（/home/your/file/to/path）
		#命令中的路径需要根据实际情况来写。

		又或者使用finalshell、xshell等集成工具完成恶意文件样本采样。
		也可使用python、php等程序发起http服务。
		或者使用netcat。
		#根据信息安全工程师习惯或者业主要求/环境要求，灵活使用。
	```
- 病毒在线分析
	- PCHunter
	- Virustotal
	- 哈勃
	- jotti
	- scanvir
	- 魔盾
	- HYBRID
	- 大圣云沙箱检测系统
	- 奇安信沙箱
	- 微步云沙箱

- 寻找病毒分析报告
	- 深信服安全响应以及EDR知识赋能平台
	- 深信服EDR团队安全情报分析
	- 深信服安全中心
	- 绿盟科技
	- 火绒安全最新资讯
	- 安全客
	- Freebuf
	- ……
- 进程查杀

	```BASH
	ps ajfx
	pstree | grep ‘pid\name’
	systemctl status <pid｜name｜>
	#大部分恶意文件都会存在守护进程和子进程，可使用ps或者直接使用pstree ｜ grep 命令查看相关进程的进程树结构。

	#如果没有子进程可以直接使用
	kill -9 pid
	#这样会直接杀掉指定的进程，但是，由这个进程产生或者由其父进程产生的子进程不会被杀。

	#如果杀掉了指定进程后，在top中发现进程起了新的子进程，就需要使用如下命令
	kill -9 -pid
	#注意，这里的pid前有一个-，表示杀掉这一整个进程组

	```

	- 进程组ID&会话ID
		- 在linux中，平常我们关注更多的是PID和PPID，对于PGID和SID接触的较少，简单提两句

	```BASH
	ps ajfx

	#使用ps ajfx参数可以看到具体的PPID、PID、PGID、SID信息。
	#具体参数可以根据场景需要灵活添加/减少
	```
	![kill_pid](./img/post_img/241019/kill_pid.jpg)
	> 当程序运行起来后,会产生一个主进程，并且分配一个进程ID(PID)，如果在运行期间，主进程又起了其他的进程，那么**这个其他进程就是该主进程的子进程**，同时会分配相应的进程ID，并且设置其PPID的值为父进程的PID。
	> 而此时，父进程和其所有生成的子进程就会形成一个进程组，并且会被分配一个进程组ID。
	> 那什么又是会话ID呢？当我们通过ssh连接远程服务器时，会获取到一个会话，同时会被分配一个会话ID，此时我们起的进程的会话ID都是一样的。（表达能力有限……大概就是平常登录游戏，里面所有的东西都是你的；个人拙见，个人拙见）
	> 所以，如果挖矿程序有调用子进程，那么一定要以进程组为单位全部杀掉！（诛九族！）
- 守护进程（daemon）
	> 恶意文件为了保证自身的稳定持续运行，通常都会为程序设置一个守护进程。而杀掉守护进程和杀掉普通进程并没有什么区别，直接一起杀掉就可以。
- 线程查杀
	> 一些恶意程序将恶意代码做到了线程级别，也就是说，恶意程序宛若寄生虫一般附在了现有生产环境中的正常生产进程中，做成了一个线程；
	> 目前能力有限，直接查杀一个正常业务进程中的线程风险很大；有很大的概率会把正常的业务进程搞崩。
	> 如果真的遇到了线程级别的恶意程序，查杀之前一定需要和业主客户沟通确认并明确风险之后在进行操作。
	> 杀线程的方法和杀进程一样；在Linux中，线程的概念，其实就是轻量级的进程。
	> ```BASH
	ps -T -p pid
	ps -aLF pid

	#根据pid查看由进程起的线程
	```
	![kill_pid2](./img/post_img/241019/kill_pid2.jpg)
	其中SPID就是线程ID，而CMD栏，则显示了线程名称。
	```BASH
	#除了ps命令之外，还有其他命令也可查看线程
	top -H -p pid
	# -H选项可以显示线程

	htop
	#默认未安装，可以较为全面的展示线程
	#Debian/Kali可使用 sudo apt-get install htop安装

	pstree -agplU
	#推荐，以树形结构展示进程和线程之间的关系

	ps -eLFa
	#查看全部的线程
	```
## **0x06_删除恶意文件**

- 通过上述操作，我们已经定位到了文件具体位置并且杀掉了恶意程序，接下来就是删除恶意文件。

- 查看文件占用
```BASH
lsof eval.sh
#如果存在进程占用，那么占用进程极大概率也是恶意程序，按照上述操作步骤进行查看排查。

a和i属性导致文件不可删除
#a属性-文件只能增加内容，不能修改之前的文件，不能删除文件
#i属性-文件内容不能改变，文件不能删除

#解决办法-可以使用以下命令
chattr -a
chattr -i
```
> 具体可以参考<https://www.cnblogs.com/kzang/articles/2673790.html>
- 奇奇怪怪的文件名导致文件无法被删除
> 从Windos想Linux传输的文件或者攻击者恶意制作的文件，会存在文件名乱码的情况，无法直接通过乱码的文件名进行删除，可以使用inode来确定文件名，之后删除

	```BASH
	#查看inode
	ls -li eval.sh
	```

	![kill_pid3](./img/post_img/241019/kill_pid3.jpg)


	```BASH
		#删除文件
		find ./* -inum 12327526 -delete
		find ./ -inum 12327526 -exec rm{} \;
		find ./ -inum 12327526 -exec rm -i {} \;
		#会提示确认是否删除

		find ./ -inum 12327526 -exec rm -f {} \;
		#不会进行确认，直接强制删除

		find ./ -inum 12327526 | xargs rm -f
		rm ‘find ./* -inum 12327526’

		```

	> 具体可参考:
	> <https://www.cnblogs.com/starry-skys/p/12970463.html>
	> <https://www.cnblogs.com/tssc/p/7574432.html>
	> 个人拙见：是否可以利用bin命令呢？没有动手尝试，只是想法。

- 目录挂载导致无法删除
> 当目录中没有文件，但是依然无法删除的时候，显示Device or resource busy
> 但是使用lsof进行查看，又发现并没有资源占用，此时需要考虑可能目录存在挂载点导致。
![kill_pid4](./img/post_img/241019/kill_pid4.jpg)
> 此时需要先将挂载取消，之后再删除该目录
	```BASH
	sudo lsblk -a
	#查看挂载情况
	```
![kill_pid5](./img/post_img/241019/kill_pid5.jpg)
> ```BASH
	sudo umount /dev/sdb1
	#注意：/dev/sdb1是演示主机终端的情况，需要按照实际情况进行更改
	```
> ![kill_pid6](./img/post_img/241019/kill_pid6.jpg)
> 如此就大公告成，成功删除掉恶意文件了。

## **0x07_善后处理**
- 关于善后……
 >按照流程来说，上述步骤已经完成了一次恶意文件样本的处置全过程
 > 接下来做的就是查看被攻击终端是否存在其他被攻击的痕迹，涉及到的方面太多，后面统一写
 > 今天就到这里。
