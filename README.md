反调试插件，只测试过IDA8.3
参考了ScyllaHide的代码

## 效果说明

### 1. 基本标志位修正

- PEB-beingDebug
- PEB-NtGlobalFlag
- PEB-HeapFlags

**TODO:**

- 父进程名检查是否是文件管理器启动
- [不实现] 检查是否有调试器窗口

### 2. 重要函数 Hook

- CheckRemoteDebuggerPresent
- NtQueryInformationProcess
  - 包括 ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags
  - 主动写入了 returnLength
- NtSetInformationThread
  - 0x11 提前 ret
- GetThreadContext
  - 检查硬件断点前提前写入空值

**TODO:**

- （这里可以添加需要实现的内容）

### 3. 时钟反调试

- 对 rdtsc 指令监控，汇编界面步过或步入使每次时钟值相同

### 4. 杂项

**TODO:**

- 支持自定义 text 段函数 Hook，强制返回某个值
- 主动对函数下断点
  - VirtualProtect
