# 授权服务器

## 授权码模式

### 请求授权码
- state随机生成

```
GET
http://localhost:8080/oauth2/authorize?client_id=ddd&client_secret=ddd&response_type=code&scope=msg.read msg.write&state=0CI0ziUDEnqMgqW0nzRNRCzLrs-9IMbqJzGZ47Zb0gY%3D&redirect_uri=https://baidu.com
```

### 获取token

- basic auth
```
curl --location --request POST 'localhost:8080/oauth2/token?grant_type=authorization_code&code=_xebJvn2_lDbCq_ZPJ4SiFu-Qd0VWh37VqTYVCxrNzP_rbtKpheKREhaG-MDXl0xlZ4oSMT3Wm690UM0N_OSr7Doav1QLbqAlMuEytTRpH09X003l9-Zjj_Yv0gZapdl&redirect_uri=https://baidu.com' \
--header 'Authorization: Basic cGlnOnBpZw=='

```

- form

```
curl --location --request POST 'localhost:8080/oauth2/token' \
--data-urlencode 'client_id=ddd' \
--data-urlencode 'client_secret=ddd' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'redirect_uri=https://baidu.com' \
--data-urlencode 'code=dVMJE3tW0HlnJsI_clTx15UvW0JOlxZxRnCQyDCzzw9P7chdmczjDTBBxDzlfDLfvd6NevYdYCs4PlqhYKXmoDv6yqqkerBpxFIllDqTysRlEKJAwUY7LcycrcWwtaDD'

```