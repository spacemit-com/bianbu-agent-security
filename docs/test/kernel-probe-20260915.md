# WEB-12 内核探针补验

原先阻塞是模型拒绝发起工具，不能据此判断内核是否拦截。新增确定性本地模型夹具，仍走真实 Runtime Run、terminal 工具、sandbox 与 seccomp，不依赖云端模型决定。

提交 c218441 增加探针；首轮真实执行已返回 EPERM 并生成 eBPF 事件，但测试错误地比较了沙箱 PID 和宿主 PID。提交 373a1d9 修正为关联本次新建 Agent、实例与 lease 后，Worker 重跑通过。

本次 Agent `com.bianbu.16c9164a238b`、Run `04397e1f-73b6-4009-a67b-a050cbaf408f`：finit_module(273, fd=-1) 返回 -1/errno=1；沙箱 PID=29，eBPF 宿主 PID=2152235，事件 seq=6，backend=ebpf-seccomp，action=deny。两端页面均已实际读取并显示本次事件（插件为真实服务预览）。

证据：[完整运行与内核事件](evidence/kernel-20260915/kernel-probe.json)、[Runtime 页面](evidence/kernel-20260915/kernel-runtime.png)、[插件页面](evidence/kernel-20260915/kernel-plugin.png)。临时 Agent/Provider 暂留用于原生桌面复验，结束后删除并补记。
