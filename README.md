b23.wtf
---

Source of b23.wtf, a tracing-free bilibili short URL service.

Here's also a browser userscript for replacing destinations to b23.tv on *.bilibili.com, hosted on [GreasyFork](https://greasyfork.org/zh-CN/scripts/435611-%E5%8E%BB%E9%99%A4%E6%A0%87%E9%A2%98%E6%8E%A9%E7%9B%96%E4%B8%8B-b23-tv-%E7%9F%AD%E9%93%BE%E6%8E%A5%E7%9A%84%E8%BF%BD%E8%B8%AA%E4%BF%A1%E6%81%AF).

Identical service is available through: **b23.wtf. b23.tf. b23.icu.**

Similar services for 小红书: https://xhslink.icu.

### APIs

`https://b23.wtf/api?full=[url]`
> 302 to URL

`https://b23.wtf/api?full=[url]&status=200`
> 200 with URL plain text

`https://b23.wtf/setautoredirect[1,0]`
> set-cookie to turn on/off unconditional auto-redirect




<!---

My own deployment notes:

```bash
b23all -t "bash -c 'cd ~/b23wtf_pkgbuild; yes | makepkg -cfi && sudo systemctl daemon-reload && sudo systemctl restart b23wtf'"
```
--->
