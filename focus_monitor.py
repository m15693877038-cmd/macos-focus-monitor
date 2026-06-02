#!/usr/bin/env python3
"""
macOS Window Focus Monitor - 实时检测偷焦点的应用
===================================================

轮询方式，简单可靠，无需理解 Cocoa run loop。

安装:
    pip3 install pyobjc-framework-Quartz pyobjc-framework-Cocoa

用法:
    python3 focus_monitor.py              # 只显示可疑事件
    python3 focus_monitor.py -v           # 显示所有焦点变化
    python3 focus_monitor.py -t 0.5       # 自定义阈值(默认0.3s)
    python3 focus_monitor.py -o log.txt   # 同时写日志文件

Ctrl+C 停止，自动输出汇总报告。
"""

import sys
import os
import time
import signal
import argparse
from datetime import datetime
from collections import defaultdict

# ── 依赖检查 ──────────────────────────────────────────
try:
    from AppKit import NSWorkspace
except ImportError:
    print("缺少依赖，请安装:")
    print("  pip3 install pyobjc-framework-Quartz pyobjc-framework-Cocoa")
    sys.exit(1)

try:
    import Quartz
except ImportError:
    print("缺少依赖，请安装:")
    print("  pip3 install pyobjc-framework-Quartz")
    sys.exit(1)
# ───────────────────────────────────────────────────────


class FocusMonitor:
    """轮询监测窗口焦点变化，标记可疑应用。"""

    def __init__(self, output_file=None, verbose=False, threshold=0.3, interval=0.1):
        self.output_file = output_file
        self.verbose = verbose
        self.threshold = threshold
        self.interval = interval  # 轮询间隔

        self.last_app_name = None
        self.last_input_time = time.time()
        self.stats = {}
        self.running = False

    def _get_stats(self, bundle_id):
        if bundle_id not in self.stats:
            self.stats[bundle_id] = {
                'total': 0, 'suspicious': 0,
                'lsui_element': None, 'floating': None,
                'name': 'Unknown', 'path': None,
            }
        return self.stats[bundle_id]

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        if self.output_file:
            try:
                with open(self.output_file, 'a') as f:
                    f.write(line + '\n')
            except IOError:
                pass

    def check_lsui_element(self, bundle_path):
        if not bundle_path:
            return False
        try:
            import plistlib
            p = os.path.join(bundle_path, 'Contents', 'Info.plist')
            if not os.path.exists(p):
                return False
            with open(p, 'rb') as f:
                return plistlib.load(f).get('LSUIElement', False) is True
        except Exception:
            return False

    def has_floating_windows(self, pid):
        try:
            wins = Quartz.CGWindowListCopyWindowInfo(
                Quartz.kCGWindowListOptionAll, Quartz.kCGNullWindowID
            )
            if not wins:
                return False
            for w in wins:
                if w.get(Quartz.kCGWindowOwnerPID) == pid:
                    if w.get(Quartz.kCGWindowLayer, 0) > 0:
                        return True
            return False
        except Exception:
            return False

    def seconds_since_input(self):
        try:
            src = Quartz.kCGEventSourceStateCombinedSessionState
            return min(
                Quartz.CGEventSourceSecondsSinceLastEventType(src, Quartz.kCGEventKeyDown),
                Quartz.CGEventSourceSecondsSinceLastEventType(src, Quartz.kCGEventLeftMouseDown),
                Quartz.CGEventSourceSecondsSinceLastEventType(src, Quartz.kCGEventMouseMoved),
            )
        except Exception:
            return float('inf')

    def _check_activation(self, app_info):
        """检测一次激活是否为偷焦点。"""
        now = time.time()
        # 用 CG 底层 API 获取精确闲置时间
        idle = self.seconds_since_input()
        self.last_input_time = now - idle
        delta = idle  # 距上次用户操作的时间

        suspicious = delta > self.threshold
        bid = app_info.get('NSApplicationBundleIdentifier') or f"pid-{app_info.get('NSApplicationProcessIdentifier', '?')}"

        s = self._get_stats(bid)
        s['total'] += 1
        s['name'] = app_info.get('NSApplicationName', 'Unknown')
        s['path'] = app_info.get('NSApplicationPath')

        if suspicious:
            s['suspicious'] += 1
            if s['lsui_element'] is None:
                s['lsui_element'] = self.check_lsui_element(app_info.get('NSApplicationPath'))
            if s['floating'] is None:
                s['floating'] = self.has_floating_windows(app_info.get('NSApplicationProcessIdentifier', 0))

            tags = []
            if s['lsui_element']:
                tags.append('LSUIElement')
            if s['floating']:
                tags.append('FloatPanel')
            if delta > 2.0:
                tags.append(f'Idle {delta:.1f}s')
            elif delta > 0.5:
                tags.append(f'Delay {delta:.1f}s')

            tag_str = f"  [{', '.join(tags)}]" if tags else ''
            self.log(
                f'\u26a0  {app_info["NSApplicationName"]}  '
                f'(PID {app_info.get("NSApplicationProcessIdentifier", "?")}, {bid})  '
                f'\u0394t={delta:.2f}s{tag_str}'
            )
        elif self.verbose:
            self.log(
                f'\u2713  {app_info["NSApplicationName"]}  '
                f'(PID {app_info.get("NSApplicationProcessIdentifier", "?")})'
            )

    def run(self):
        """主轮询循环。"""
        ws = NSWorkspace.sharedWorkspace()

        print('\u2550' * 50, flush=True)
        print('  macOS Focus Monitor - 实时偷焦点检测', flush=True)
        print('\u2550' * 50, flush=True)
        print(f'  阈值: {self.threshold}s | 轮询间隔: {self.interval}s | Ctrl+C 停止\n', flush=True)

        self.running = True
        try:
            while self.running:
                active = ws.activeApplication()
                name = active.get('NSApplicationName', '')
                if name != self.last_app_name:
                    self.last_app_name = name
                    self._check_activation(active)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
            self.print_report()

    def print_report(self):
        sep = '\u2500' * 50
        print(f'\n{sep}\n  实时监测报告\n{sep}', flush=True)

        bad = {k: v for k, v in self.stats.items() if v['suspicious'] > 0}
        if not bad:
            print('\n\u2705  未发现偷焦点行为\n', flush=True)
            return

        print(f'\n\u26a0  发现 {len(bad)} 个可疑应用:\n', flush=True)
        for bid, s in sorted(bad.items(), key=lambda x: -x[1]['suspicious']):
            pct = s['suspicious'] / s['total'] * 100
            tags = []
            if s['lsui_element']:
                tags.append('LSUIElement(无Dock图标)')
            if s['floating']:
                tags.append('FloatPanel(浮动窗口)')
            if pct > 50 and s['total'] >= 3 and not tags:
                tags.append('疑似 activateIgnoringOtherApps/makeMeKeyWindow')

            print(f'  \U0001f4f1 {s["name"]}  [{bid}]', flush=True)
            print(f'     可疑/总计: {s["suspicious"]}/{s["total"]}  ({pct:.0f}%)', flush=True)
            if tags:
                sep_tags = ', '
                print(f'     手段: {sep_tags.join(tags)}', flush=True)
            if s.get('path'):
                print(f'     路径: {s["path"]}', flush=True)
            print(flush=True)


def main():
    parser = argparse.ArgumentParser(
        description='macOS 实时焦点监测（轮询方式）',
        epilog='示例: python3 focus_monitor.py -v',
    )
    parser.add_argument('-o', '--output', help='日志文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示所有焦点变化')
    parser.add_argument('-t', '--threshold', type=float, default=0.3,
                        help='可疑阈值秒数 (默认 0.3)')
    parser.add_argument('-i', '--interval', type=float, default=0.1,
                        help='轮询间隔秒数 (默认 0.1)')
    args = parser.parse_args()

    monitor = FocusMonitor(
        output_file=args.output,
        verbose=args.verbose,
        threshold=args.threshold,
        interval=args.interval,
    )

    def shutdown(signum=None, frame=None):
        monitor.running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    monitor.run()


if __name__ == '__main__':
    main()
