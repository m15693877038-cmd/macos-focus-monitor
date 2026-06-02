#!/usr/bin/env python3
"""
macOS Window Focus Monitor - Detect apps that steal focus

Monitors all window focus changes and identifies potential focus-stealing
behavior by analyzing the timing between user input events and app activations.

Detected focus-stealing tactics:
  - activateIgnoringOtherApps  — Forcibly activating an app's windows
  - makeMeKeyWindow            — Forcing a window to become the key window
  - FloatPanel                 — Creating floating overlay windows
  - LSUIElement = true         — Running in hidden/background mode without Dock icon

Usage:
  python3 focus_monitor.py              # Basic monitoring
  python3 focus_monitor.py -v           # Verbose: show all focus changes
  python3 focus_monitor.py -o log.txt   # Save log to file
  python3 focus_monitor.py -j report.json  # Save JSON report on exit
"""

import sys
import time
import os
import signal
import json
import argparse
from datetime import datetime
from collections import defaultdict

import Quartz
from AppKit import (
    NSWorkspace,
    NSWorkspaceDidActivateApplicationNotification,
    NSWorkspaceApplicationKey,
    NSObject,
    NSTimer,
)
from Foundation import (
    NSDate,
    CFRunLoopRun,
    CFRunLoopStop,
    CFRunLoopGetCurrent,
)


class AppObserver(NSObject):
    """ObjC observer class to receive NSWorkspace notifications."""

    def initWithMonitor_(self, monitor):
        self = self.init()
        if self:
            self._monitor = monitor
        return self

    def handleAppActivation_(self, notification):
        """Called when NSWorkspaceDidActivateApplicationNotification fires."""
        user_info = notification.userInfo()
        running_app = user_info.get(NSWorkspaceApplicationKey) if user_info else None

        app_info = {}
        if running_app:
            app_info['pid'] = running_app.processIdentifier()
            app_info['name'] = running_app.localizedName() or 'Unknown'
            app_info['bundle_id'] = running_app.bundleIdentifier() or f"pid-{app_info['pid']}"
            bundle_url = running_app.bundleURL()
            app_info['bundle_path'] = bundle_url.path() if bundle_url else None
        else:
            return

        if self._monitor:
            self._monitor.process_activation(app_info)


class FocusMonitor:
    """Monitors window focus changes and detects focus-stealing behavior."""

    SUSPICIOUS_DEFAULT = 0.3
    INPUT_POLL_INTERVAL = 0.1

    def __init__(self, output_file=None, verbose=False, suspicious_threshold=None):
        self.output_file = output_file
        self.verbose = verbose
        self.suspicious_threshold = suspicious_threshold or self.SUSPICIOUS_DEFAULT

        self.last_user_input_time = time.time()
        self.focus_events = []
        self.app_stats = {}
        self.running = False
        self._observer = None

    def _get_stats(self, bundle_id):
        if bundle_id not in self.app_stats:
            self.app_stats[bundle_id] = {
                'total_activations': 0,
                'suspicious_activations': 0,
                'first_seen': None,
                'last_seen': None,
                'is_lsui_element': None,
                'has_floating_windows': None,
                'bundle_id': bundle_id,
                'bundle_path': None,
                'app_name': 'Unknown',
            }
        return self.app_stats[bundle_id]

    def log(self, msg):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        line = f"[{timestamp}] {msg}"
        print(line, flush=True)
        if self.output_file:
            try:
                with open(self.output_file, 'a') as f:
                    f.write(line + '\n')
            except IOError:
                pass

    def check_lsui_element(self, bundle_path):
        """Check if an app has LSUIElement = true in its Info.plist."""
        if not bundle_path:
            return False
        try:
            import plistlib
            plist_path = os.path.join(bundle_path, 'Contents', 'Info.plist')
            if not os.path.exists(plist_path):
                return False
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
            return plist.get('LSUIElement', False) is True
        except Exception:
            return False

    def has_floating_windows(self, pid):
        """Check if an app has windows on floating layers (window level > 0)."""
        try:
            window_list = Quartz.CGWindowListCopyWindowInfo(
                Quartz.kCGWindowListOptionAll,
                Quartz.kCGNullWindowID,
            )
            if not window_list:
                return False
            for window in window_list:
                if window.get(Quartz.kCGWindowOwnerPID) == pid:
                    level = window.get(Quartz.kCGWindowLayer, 0)
                    if level > 0:
                        return True
            return False
        except Exception:
            return False

    def seconds_since_last_input(self):
        """Get minimum seconds since last user input event."""
        try:
            source = Quartz.kCGEventSourceStateCombinedSessionState
            last_key = Quartz.CGEventSourceSecondsSinceLastEventType(
                source, Quartz.kCGEventKeyDown
            )
            last_click = Quartz.CGEventSourceSecondsSinceLastEventType(
                source, Quartz.kCGEventLeftMouseDown
            )
            last_move = Quartz.CGEventSourceSecondsSinceLastEventType(
                source, Quartz.kCGEventMouseMoved
            )
            return min(last_key, last_click, last_move)
        except Exception:
            return float('inf')

    def poll_user_input(self):
        """Poll and update last user input time."""
        idle = self.seconds_since_last_input()
        self.last_user_input_time = time.time() - idle

    def process_activation(self, app_info):
        """Process an app activation event."""
        if not app_info or not app_info.get('pid'):
            return

        now = time.time()
        time_since_input = now - self.last_user_input_time
        is_suspicious = time_since_input > self.suspicious_threshold

        bundle_id = app_info['bundle_id']
        stats = self._get_stats(bundle_id)
        stats['total_activations'] += 1
        stats['last_seen'] = datetime.now().isoformat()
        if stats['first_seen'] is None:
            stats['first_seen'] = datetime.now().isoformat()
        stats['bundle_path'] = app_info.get('bundle_path')
        stats['app_name'] = app_info.get('name', 'Unknown')

        if is_suspicious:
            stats['suspicious_activations'] += 1

            if stats['is_lsui_element'] is None:
                stats['is_lsui_element'] = self.check_lsui_element(
                    app_info.get('bundle_path')
                )
            if stats['has_floating_windows'] is None:
                stats['has_floating_windows'] = self.has_floating_windows(
                    app_info['pid']
                )

            flags = []
            if stats['is_lsui_element']:
                flags.append('LSUIElement')
            if stats['has_floating_windows']:
                flags.append('FloatPanel')
            if time_since_input > 2.0:
                flags.append(f'Idle({time_since_input:.1f}s)')
            elif time_since_input > 0.5:
                flags.append(f'Delayed({time_since_input:.1f}s)')

            flag_str = f"  [{', '.join(flags)}]" if flags else ''
            self.log(
                f'\u26a0\ufe0f  FOCUS STEAL: {app_info["name"]} '
                f'(PID:{app_info["pid"]}, {bundle_id}) '
                f'| \u0394t:{time_since_input:.2f}s{flag_str}'
            )
        elif self.verbose:
            self.log(
                f'\u2713   Focus OK: {app_info["name"]} '
                f'(PID:{app_info["pid"]}, {bundle_id})'
            )

        self.focus_events.append({
            'timestamp': datetime.now().isoformat(),
            'app_name': app_info['name'],
            'bundle_id': bundle_id,
            'pid': app_info['pid'],
            'time_since_input': round(time_since_input, 3),
            'is_suspicious': is_suspicious,
        })

        if len(self.focus_events) > 10000:
            self.focus_events = self.focus_events[-5000:]

    def generate_report(self):
        """Generate a summary report."""
        sep = '=' * 58
        self.log(f'\n{sep}')
        self.log('FOCUS MONITORING REPORT')
        self.log(sep)

        suspicious = {
            bid: s for bid, s in self.app_stats.items()
            if s['suspicious_activations'] > 0
        }

        if not suspicious:
            self.log('\n\u2705 No suspicious focus-stealing detected.')
            return

        self.log(f'\n\U0001f50d Found {len(suspicious)} potential focus thief(s):\n')

        sorted_apps = sorted(
            suspicious.items(),
            key=lambda x: x[1]['suspicious_activations'],
            reverse=True,
        )

        for bundle_id, s in sorted_apps:
            ratio = (s['suspicious_activations'] / s['total_activations']) * 100

            methods = []
            if s['is_lsui_element']:
                methods.append('LSUIElement (no Dock icon, runs hidden)')
            if s['has_floating_windows']:
                methods.append('FloatPanel (floating window layer)')
            if ratio > 50 and s['total_activations'] >= 3:
                if not methods:
                    methods.append(
                        'Likely activateIgnoringOtherApps / makeMeKeyWindow'
                    )

            self.log(f'  \U0001f4f1 {s["app_name"]}  [{bundle_id}]')
            self.log(
                f'     Suspicious: {s["suspicious_activations"]}/'
                f'{s["total_activations"]} ({ratio:.0f}%)'
            )
            if methods:
                self.log(f'     Methods: {", ".join(methods)}')
            if s['bundle_path']:
                self.log(f'     Path: {s["bundle_path"]}')
            self.log('')

        total_suspicious = sum(
            1 for e in self.focus_events if e['is_suspicious']
        )
        self.log(
            f'Total events: {len(self.focus_events)}  '
            f'Suspicious: {total_suspicious}'
        )

    def save_json_report(self, filepath):
        """Save detailed report as JSON."""
        def default_serializer(o):
            return str(o)

        report = {
            'generated_at': datetime.now().isoformat(),
            'threshold_seconds': self.suspicious_threshold,
            'total_events': len(self.focus_events),
            'suspicious_events': sum(
                1 for e in self.focus_events if e['is_suspicious']
            ),
            'app_stats': self.app_stats,
            'events': self.focus_events[-1000:],
        }
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=default_serializer)
        self.log(f'\n\U0001f4c4 JSON report saved to: {filepath}')

    def start(self):
        """Start monitoring — blocking call."""
        separator = '=' * 58
        self.log(separator)
        self.log('macOS Focus Monitor v1.0')
        self.log(separator)
        self.log(
            f'Suspicious threshold: {self.suspicious_threshold}s '
            f'without user input'
        )
        self.log('Press Ctrl+C to stop and generate report.\n')

        self.running = True

        # Set up NSWorkspace notification observer
        ws = NSWorkspace.sharedWorkspace()
        nc = ws.notificationCenter()
        self._observer = AppObserver.alloc().initWithMonitor_(self)
        nc.addObserver_selector_name_object_(
            self._observer,
            'handleAppActivation:',
            NSWorkspaceDidActivateApplicationNotification,
            None,
        )

        # Add the pollInputTimer: method dynamically
        def poll_input_timer(self_, timer_):
            if self_.monitor() and self_.monitor().running:
                self_.monitor().poll_user_input()

        def monitor(self_):
            return self_._monitor

        import objc
        AppObserver.monitor = monitor
        AppObserver.pollInputTimer_ = poll_input_timer

        # Schedule timer for polling user input
        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            self.INPUT_POLL_INTERVAL,
            self._observer,
            'pollInputTimer:',
            None,
            True,
        )

        try:
            CFRunLoopRun()
        except KeyboardInterrupt:
            self.running = False

    def stop(self):
        """Stop monitoring."""
        self.running = False
        CFRunLoopStop(CFRunLoopGetCurrent())


def main():
    parser = argparse.ArgumentParser(
        description='macOS Window Focus Monitor \u2014 Detect focus-stealing apps',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 focus_monitor.py                   # Basic monitoring
  python3 focus_monitor.py -v                # Show all focus changes
  python3 focus_monitor.py -o focus.log      # Save log to file
  python3 focus_monitor.py -j report.json    # JSON report on exit
  python3 focus_monitor.py -t 0.5 -v         # Custom threshold + verbose
        ''',
    )
    parser.add_argument('-o', '--output', help='Log output file path')
    parser.add_argument(
        '-j', '--json',
        help='Save JSON report to specified file on exit',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all focus changes, not just suspicious ones',
    )
    parser.add_argument(
        '-t', '--threshold',
        type=float,
        default=FocusMonitor.SUSPICIOUS_DEFAULT,
        help=(
            'Time threshold in seconds for suspicious detection '
            f'(default: {FocusMonitor.SUSPICIOUS_DEFAULT})'
        ),
    )

    args = parser.parse_args()

    monitor = FocusMonitor(
        output_file=args.output,
        verbose=args.verbose,
        suspicious_threshold=args.threshold,
    )

    def shutdown(signum=None, frame=None):
        print('\n\n\U0001f6d1 Shutting down...', flush=True)
        monitor.generate_report()
        if args.json:
            monitor.save_json_report(args.json)
        if monitor.running:
            monitor.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    monitor.start()


if __name__ == '__main__':
    main()
