# ida2pwntools
ida2pwntools 是一款IDA 7.0上的插件，用于远程连接pwntools启动的程序进行pwn调试。

# 安装

将 ida2pwntools.py 放入IDA安装目录下的 plugins 目录即可。

在IDA中 加载elf文件后会在最右侧显示ida2pwntools菜单表示安装成功。

# 使用
- IDA 中配置好远端服务器地址（Debugger->Process options->Hostname/Port）
- 在远端服务器启动IDA提供的linux_server / linux_server64 等
- 在ida2pwntools菜单中，点击connect to pwntools，插件会等待同名程序启动
![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/2start_plugin.png?raw=true)

- 在使用pwntools的脚本exp.py中，增加wait_for_debugger代码
```
from pwn import *
from pwnlib.util.proc import wait_for_debugger
io = process("silent", stdin=PTY)
wait_for_debugger(io.pid)
```
![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/1wait_for_debugger.png?raw=true)

- 插件连接pwntools成功后，即可在IDA和pwntools中调试

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/3attached_in_pwntools.png?raw=true)

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/4attached_in_ida.png?raw=true)
 
# 适用版本
IDA 7.0

