### 0x01 概述
轻量化端口扫描工具，解决一些小场景下没必要用平台，但又希望扫描尽可能快和准，又不希望工具过重装很多依赖；扫描方式还是老一套采用masscan+nmap+top1000，主要用来方便平时使用、改善部分同类工具中一些小问题。

---

### 0x02 运行
```bash
pip install python-libnmap gevent requests --user
nmap / masscan

root@localhost :~#  python DiscoverPort.py ips.txt

# Tip:
# 使用上默认采用静默输出方式，如果需要shell查看输出信息或者一些其他扫描参数、线程的修改，直接脚本中改。
# 如果需要过WAF，修改nmap数据包格式和指纹编译。
``` 
![](https://hack-1259805894.cos.ap-shanghai.myqcloud.com/port2.png)
![](https://hack-1259805894.cos.ap-shanghai.myqcloud.com/port.png)