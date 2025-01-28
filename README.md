### 近期目标
- 优化日志库和基础数据库的耦合部分，重构日志库接口；(暂时剔除了基础库中的日志接口)
- 基础数据结构接口库（队列、链表、线程、定时器等）；
- 学习shell脚本中对于文本处理的部分（awk）
- FFMPEG接口库实现，流媒体处理；
- 编写README;
- 基于GTEST编写各模块接口测试用例；
- 学习git多分支开发经验
- 学习网络通信编程；
- 学习数据库，数据库文件本身可以进行加密/解密操作，数据更安全；
- 本地编译gtest，构建本地单元测试环境  暂时无法实现，优先级降低
- ......

### 已支持功能
1. 轻量级异步日志库
    - 支持多线程调用；
    - 内部使用了环形队列，内存占用可控；
    - 支持遗言日志；
    - 支持配置文件，且提供运行时动态修改日志配置的接口；
    - 支持多等级日志，且独立输出错误日志文件，程序问题一眼定位；
    - 提供字节流日志输出接口；
    - 每条日志都支持输出到指定文件；
    - 定时（24H）输出IO统计；
    - 支持彩色日志
    - ......

2. 通用文件加密/解密库；
    - 解耦的文件加密/解密代码开发框架；
    - 目前支持对称加密算法 256位AES加密
    - ......

3. 通用接口库
    - 已支持基于EPOLL实现的定时器，相较于其他传统定时器，在要求多定时器的环境上，性能表现更优
    - ......

### 工程架构特点
- 代码支持跨平台编译（x86/x64/arm）；
- 每个模块都配套支持GTEST本地单元测试；
- 每个模块可独立编译为动态/静态库
- ......