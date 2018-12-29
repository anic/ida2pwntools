# ida2pwntools
ida2pwntools 是一款IDA 7.0上的插件，用于远程连接pwntools启动的程序进行pwn调试。

# 安装

将 ida2pwntools.py 放入IDA安装目录下的 plugins 目录即可。

在IDA中 加载elf文件后会在最右侧显示ida2pwntools菜单表示安装成功。

# 使用
## 准备
- IDA 中配置好远端服务器地址（Debugger->Process options->Hostname/Port）
- IDA 中配置好需要加载的程序名字（Debugger->Process options->Application），只填写程序名，不要带路径。ida2pwntools会根据这个名字找进程
- 在远端服务器启动IDA提供的linux_server / linux_server64 等
- 在使用pwntools的脚本exp.py中，增加wait_for_debugger代码
```
from pwn import *
from pwnlib.util.proc import wait_for_debugger
io = process("silent", stdin=PTY)
wait_for_debugger(io.pid)
```

## 调试
- 方法1 ：用快捷键尝试一次加载

先启动exp.py，执行到wait_for_debugger等待程序被调试。切换到IDA中按快捷键F12启动ida2pwntools插件，插件会查找进程尝试进行一次加载。

- 方法2 ：用窗口尝试等待加载

在IDA中的ida2pwntools菜单，点击“connect to pwntools”，插件弹出等待窗口等待同名程序启动。然后启动exp.py，运行至wait_for_debugger，程序自动会被挂载上。

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/2start_plugin.png?raw=true)

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/1wait_for_debugger.png?raw=true)

- 插件连接pwntools成功后，即可在IDA和pwntools中调试

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/3attached_in_pwntools.png?raw=true)

![image](https://github.com/anic/ida2pwntools/blob/master/screenshot/4attached_in_ida.png?raw=true)
 
# 适用版本
IDA 7.0

# 注意事项
- 使用快捷键F12只能尝试一次加载，因为IDA中对于脚本运行有限制。
- 为了调试更快捷，建议关闭Source-Level（Debugger->Use source-level debugging），否则一旦连接到远程程序，IDA就会弹出各种警告提示框让你确认。

