"""
lib/version_detect.py — Chrome 版本检测 + Hook 配置加载

T5.3:
- 自动检测 Chrome 版本号
- 从 hooks/ 目录加载对应 JSON
- 构建注入 %HOOK_CONFIG% 的 Frida Hook 脚本
"""

import json
import os
import re
import subprocess


DEFAULT_CHROME_BINARIES = [
    '/opt/google/chrome/chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
]


def detect_chrome_version(binary_path='/opt/google/chrome/chrome'):
    """检测 Chrome 版本号。

    尝试顺序：
        1. binary --version
        2. 备用 Chrome 可执行文件 --version
        3. Last Version 文件

    Returns:
        版本字符串如 "143.0.7499.169"，或 None
    """
    for candidate in _candidate_binaries(binary_path):
        version = _detect_from_binary(candidate)
        if version:
            return version

    for path in [
        os.path.expanduser('~/.config/google-chrome/Last Version'),
        '/tmp/chrome_p3_test/Last Version',
    ]:
        try:
            with open(path) as f:
                version = f.read().strip()
            if _is_version(version):
                return version
        except Exception:
            continue

    return None


def load_config(version, config_dir=None):
    """加载对应版本的 Hook 配置 JSON。

    查找顺序：
        1. 精确匹配 meta.version
        2. 大版本匹配（前两段，如 143.0）

    Returns:
        配置字典或 None
    """
    if config_dir is None:
        config_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'hooks'
        )

    if not os.path.isdir(config_dir):
        return None

    configs = []
    for fname in os.listdir(config_dir):
        if not fname.endswith('.json'):
            continue
        fpath = os.path.join(config_dir, fname)
        try:
            with open(fpath) as f:
                cfg = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        cfg_version = cfg.get('meta', {}).get('version', '')
        if not _is_version(cfg_version):
            continue

        cfg['_config_path'] = fpath
        configs.append(cfg)

    if not configs:
        return None

    for cfg in configs:
        if cfg['meta']['version'] == version:
            cfg['_match_type'] = 'exact'
            return cfg

    major = '.'.join(version.split('.')[:2])
    for cfg in configs:
        if cfg['meta']['version'].startswith(major + '.'):
            cfg['_match_type'] = 'major'
            return cfg

    return None


def build_hook_script(config, hooks_dir=None):
    """把版本配置注入 chrome_hooks.js 模板，生成最终 Frida 脚本。"""
    if hooks_dir is None:
        hooks_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'hooks'
        )

    template_path = os.path.join(hooks_dir, 'chrome_hooks.js')
    with open(template_path) as f:
        template = f.read()

    if '%HOOK_CONFIG%' not in template:
        raise ValueError('chrome_hooks.js 缺少 %HOOK_CONFIG% 占位符')

    hook_config = _build_hook_config(config)
    injected = json.dumps(hook_config, ensure_ascii=False, indent=2)
    return template.replace('%HOOK_CONFIG%', injected)


def find_chrome_network_pid(user_data_dir):
    """查找属于指定 user-data-dir 的 Chrome NetworkService 进程。"""
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        try:
            with open(f'/proc/{entry.name}/cmdline', 'rb') as f:
                cmd = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
            if 'NetworkService' in cmd and user_data_dir in cmd:
                return int(entry.name)
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return None


def _build_hook_config(config):
    """从完整 JSON 提炼出 Hook 脚本实际需要的最小配置。"""
    hook_points = config.get('hook_points', {})
    struct_offsets = config.get('struct_offsets', {})
    tls13_offsets = config.get('tls13_key_len_offsets', {})

    return {
        'meta': {
            'browser': config.get('meta', {}).get('browser'),
            'version': config.get('meta', {}).get('version'),
            'match_type': config.get('_match_type', 'unknown'),
        },
        'hook_points': {
            'prf': {
                'rva': hook_points.get('prf', {}).get('rva'),
            },
            'key_expansion': {
                'rva': hook_points.get('key_expansion', {}).get('rva'),
            },
            'hkdf': {
                'rva': hook_points.get('hkdf', {}).get('rva'),
            },
            'ssl_log_secret': {
                'rva': hook_points.get('ssl_log_secret', {}).get('rva'),
            },
        },
        'tls13_label_map': config.get('tls13_label_map', {}),
        'tls13_key_len_offsets': {
            'c e traffic': tls13_offsets.get('c_e_traffic'),
            'c hs traffic': tls13_offsets.get('c_hs_traffic'),
            's hs traffic': tls13_offsets.get('s_hs_traffic'),
            'c ap traffic': tls13_offsets.get('c_ap_traffic'),
            's ap traffic': tls13_offsets.get('s_ap_traffic'),
            'exp master': tls13_offsets.get('exp_master'),
        },
        'struct_offsets': {
            'ssl_st_rbio': struct_offsets.get('ssl_st_rbio', '0x240'),
            'bio_st_num': struct_offsets.get('bio_st_num', '0x03c'),
        },
    }


def _candidate_binaries(binary_path):
    seen = set()
    for candidate in [binary_path, *DEFAULT_CHROME_BINARIES]:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        yield candidate


def _detect_from_binary(binary_path):
    if not binary_path or not os.path.exists(binary_path):
        return None
    try:
        out = subprocess.check_output(
            [binary_path, '--version'],
            timeout=5,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _is_version(value):
    return bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+', value or ''))
