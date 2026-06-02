#!/usr/bin/env python3
"""
macOS Window Focus Monitor - 实时检测偷焦点的应用
===================================================

安装:
    pip3 install -r requirements.txt
    然后去 系统设置 → 隐私与安全性 → 辅助功能 勾选终端

用法:
    python3 focus_monitor.py              # 只显示可疑事件
    python3 focus_monitor.py -v           # 显示所有焦点变化
    python3 focus_monitor.py -t 0.5       # 自定义阈值(默认0.3s)
    python3 focus_monitor.py -o log.txt   # 同时写日志文件

Ctrl+C 停止，自动输出汇总报告。
"""

import sys
import os

# ── 依赖检查 ──────────────────────────────────────────
MISSING = []
try:
    import Quartz
except ImportError:
    MISSING.append("pyobjc-framework-Quartz")
try:
    from AppKit import (
        NSWorkspace, NSWorkspaceDidActivateApplicationNotification,
        NSWorkspaceApplicationKey, NSObject, NSTimer,
    )
except ImportError:
    MISSING.append("pyobjc-framework-Cocoa")
try:
    from Foundation import CFRunLoopRun, CFRunLoopStop, CFRunLoopGetCurrent
except ImportError:
    pass  # included in Cocoa framework

if MISSING:
    print("缺少依赖，请先安装:")
    print(f"  pip3 install {' '.join(MISSING)}")
    print("或一步到位:")
    print("  pip3 install -r requirements.txt")
    sys.exit(1)
# ───────────────────────────────────────────────────────

import time
import signal
import argparse
from datetime import datetime
from collections import defaultdict


class AppObserver(NSObject):
    """接收 NSWorkspace 通知的 ObjC 观察者。"""

    def initWithMonitor_(self, monitor):
        self = self.init()
        if self:
            self._monitor = monitor
        return self

    def handleAppActivation_(self, notification):
        user_info = notification.userInfo()
        running_app = user_info.get(NSWorkspaceApplicationKey) if user_info else None
        if not running_app:
            return
        app_info = {
            'pid': running_app.processIdentifier(),
            'name': running_app.localizedName() or 'Unknown',
            'bundle_id': running_app.bundleIdentifier() or f"pid-{running_app.processIdentifier()}",
        }
        bundle_url = running_app.bundleURL()
        app_info['bundle_path'] = bundle_url.path() if bundle_url else None

        if self._monitor:
            self._monitor.process_activation(app_info)


class FocusMonitor:
    """实时监测焦点变化并标记可疑行为。"""

    def __init__(self, output_file=None, verbose=False, threshold=0.3):
        self.output_file = output_file
        self.verbose = verbose
        self.threshold = threshold
        self.last_input_time = time.time()
        self.stats = {}
        self.running = False

    def _get_stats(self, bundle_id):
        if bundle_id not in self.stats:
            self.stats[bundle_id] = {
                'total': 0, 'suspicious': 0,
                'lsui_element': None, 'floating': None,
                'name': 'Unknown',
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

    def poll_input(self):
        idle = self.seconds_since_input()
        self.last_input_time = time.time() - idle

    def process_activation(self, app_info):
        if not app_info:
            return

        now = time.time()
        delta = now - self.last_input_time
        suspicious = delta > self.threshold
        bid = app_info['bundle_id']

        s = self._get_stats(bid)
        s['total'] += 1
        s['name'] = app_info.get('name', 'Unknown')

        if suspicious:
            s['suspicious'] += 1
            if s['lsui_element'] is None:
                s['lsui_element'] = self.check_lsui_element(app_info.get('bundle_path'))
            if s['floating'] is None:
                s['floating'] = self.has_floating_windows(app_info['pid'])

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
                f'\u26a0  {app_info["name"]}  '
                f'(PID {app_info["pid"]}, {bid})  '
                f'\u0394t={delta:.2f}s{tag_str}'
            )
        elif self.verbose:
            self.log(
                f'\u2713  {app_info["name"]}  '
                f'(PID {app_info["pid"]})'
            )

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
                sep = ', '; print(f'     手段: {sep.join(tags)}', flush=True)
            print(flush=True)

    def start(self):
        print('\u2550' * 50, flush=True)
        print('  macOS Focus Monitor - 实时偷焦点检测', flush=True)
        print('\u2550' * 50, flush=True)
        print(f'  阈值: {self.threshold}s  |  Ctrl+C 停止并出报告\n', flush=True)

        self.running = True
        ws = NSWorkspace.sharedWorkspace()
        self._observer = AppObserver.alloc().initWithMonitor_(self)
        ws.notificationCenter().addObserver_selector_name_object_(
            self._observer, 'handleAppActivation:',
            NSWorkspaceDidActivateApplicationNotification, None,
        )

        def poll_input_timer(self_, timer_):
            m = self_.monitor()
            if m and m.running:
                m.poll_input()

        AppObserver.monitor = lambda s: s._monitor
        AppObserver.pollInputTimer_ = poll_input_timer

        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            0.1, self._observer, 'pollInputTimer:', None, True,
        )

        try:
            CFRunLoopRun()
        except KeyboardInterrupt:
            self.running = False
            self.print_report()

    def stop(self):
        self.running = False
        CFRunLoopStop(CFRunLoopGetCurrent())


def main():
    parser = argparse.ArgumentParser(
        description='macOS 实时焦点监测',
        epilog='示例: python3 focus_monitor.py -v -t 0.5',
    )
    parser.add_argument('-o', '--output', help='日志文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示所有焦点变化')
    parser.add_argument('-t', '--threshold', type=float, default=0.3,
                        help='可疑阈值秒数 (默认 0.3)')
    args = parser.parse_args()

    monitor = FocusMonitor(
        output_file=args.output,
        verbose=args.verbose,
        threshold=args.threshold,
    )

    def shutdown(signum=None, frame=None):
        print('\n\U0001f6d1 正在停止...', flush=True)
        monitor.print_report()
        if monitor.running:
            monitor.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    monitor.start()


if __name__ == '__main__':
    main()
