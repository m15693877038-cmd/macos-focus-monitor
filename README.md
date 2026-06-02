# macOS Focus Monitor

**监测 macOS 窗口焦点抢占行为，保护输入隐私。**

macOS 上部分应用会在后台抢占窗口焦点，导致正在输入的内容意外切到其他窗口——密码、聊天记录可能误入陌生输入框。部分应用还具备自动截图能力。

本脚本实时监控窗口焦点变动，帮助定位存在焦点抢占行为的软件。

---

## 安装与运行

```bash
# 1. 克隆仓库
git clone https://github.com/m15693877038-cmd/macos-focus-monitor.git
cd macos-focus-monitor

# 2. 安装依赖
pip3 install pyobjc-framework-Quartz pyobjc-framework-Cocoa

# 3. 授予辅助功能权限（必须！）
#    系统设置 → 隐私与安全性 → 辅助功能 → 勾选终端

# 4. 运行
python3 focus_monitor.py -v
```

`Ctrl+C` 停止，自动输出汇总报告。

---

## 用法

```bash
python3 focus_monitor.py              # 只显示可疑事件
python3 focus_monitor.py -v           # 显示所有焦点变化
python3 focus_monitor.py -t 0.5       # 自定义阈值（默认 0.3s）
python3 focus_monitor.py -o log.txt   # 同时写日志文件
```

| 参数 | 说明 |
|------|------|
| `-v` | 显示所有焦点切换，包括正常的 |
| `-t 0.5` | 调高阈值减少误报，调低更灵敏 |
| `-o log.txt` | 保存到文件，方便回溯 |
| `-i 0.2` | 轮询间隔（默认 0.1s） |

---

## 如何识别

### 正常切换
```
[14:35:12] ✓  Safari  (PID 1234)
```
用户主动点击切换的。

### 可疑切换
```
[14:35:15] ⚠  示例应用  (PID 5678, com.example.app)  Δt=2.10s  [LSUIElement]
```
未检测到键盘鼠标操作，应用自行激活到前台。

### 标记含义

| 标记 | 含义 | 关注度 |
|------|------|:---:|
| `LSUIElement` | 无 Dock 图标，后台运行 | 🔴 高 |
| `FloatPanel` | 浮动窗口层级，容易覆盖其他窗口 | 🔴 高 |
| `Idle 10s` | 闲置超过 10 秒后自行激活 | 🟡 中 |
| `Delay 0.5s` | 用户操作后半秒自行激活 | 🟡 中 |

### 报告怎么看

```
⚠  发现 2 个可疑应用:

  📱 示例应用  [com.example.app]
     可疑/总计: 48/52  (92%)          ← 52次激活中48次非用户触发
     手段: LSUIElement(无Dock图标), FloatPanel(浮动窗口)
     路径: /Applications/示例应用.app
     🔍 定位: open -R "/Applications/示例应用.app"
     🚫 禁用: mv "/Applications/示例应用.app" "/Applications/示例应用_disabled.app"
     💡 改名后该应用无法被自动触发
```

比例判断：
- **> 70%**：焦点抢占行为较频繁，建议关注
- **30%-70%**：存在部分非用户触发的激活，可继续观察
- **< 30%**：大概率正常行为或环境因素

---

### 焦点切换日志

```
```

### 本地数据路径

| 路径 | 说明 |
|------|------|

> 💡 如果担心隐私，可在系统设置中检查该应用的辅助功能和屏幕录制权限。

## 常见焦点抢占手段

macOS 开发文档中提供的应用激活方式：

| 技术手段 | 说明 |
|------|------|
| `activateIgnoringOtherApps:` | 激活自身窗口，不响应其他应用 |
| `makeKeyWindow` | 将窗口设为当前焦点窗口 |
| 浮动窗口层级 | 窗口始终保持在上层 |
| `LSUIElement = true` | 无 Dock 图标的后台运行模式 |

---

## 检测原理

```
while 持续运行:
    查当前前台应用
    如果切换了:
        读取用户最后操作时间
        时间差超过阈值 → 记录
        读取 Info.plist → 检查 LSUIElement
        查询窗口层级 → 检查浮动窗口
    间隔 0.1 秒
```

---

## 系统要求

- macOS 10.14+
- Python 3.8+

## License

MIT
