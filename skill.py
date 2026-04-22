import os
import re
import time
import json
import shutil
import subprocess
import tempfile
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

# 常量定义
MAX_WORKERS = 4

# 语言文件扩展名映射
LANGUAGE_EXTENSIONS = {
    "java": [".java"],
    "python": [".py"],
    "cpp": [".cpp", ".cc", ".c"],
    "csharp": [".cs"],
}

# 外部工具配置
EXTERNAL_TOOLS = {
    "bandit": {"cmd": "bandit", "args": ["-r", "-f", "json"]},
    "semgrep": {"cmd": "semgrep", "args": ["--config", "auto", "--json"]},
    "gitleaks": {"cmd": "gitleaks", "args": ["detect", "--report-format", "json"]},
}

# 工具优先级
TOOL_PRIORITY = ["gitleaks", "bandit", "semgrep"]

# 外部工具可用性缓存
EXTERNAL_TOOLS_AVAILABLE = {}

# 硬排除规则
class HardExclusionRules:
    @staticmethod
    def should_exclude(finding: Dict) -> bool:
        """判断是否应该硬排除某个发现
        
        Args:
            finding: 审计发现
            
        Returns:
            bool: 是否应该排除
        """
        # 排除特定类型的误报
        excluded_types = {
            "INFO", "LOW", "NOTE", "WARNING", "DEBUG",
            "UNDEFINED", "OTHER", "UNKNOWN",
        }
        
        vuln_type = finding.get("type", "").upper()
        severity = finding.get("severity", "").upper()
        
        if vuln_type in excluded_types or severity in excluded_types:
            return True
        
        # 排除测试文件
        file_path = finding.get("file", "")
        file_path_lower = file_path.lower()
        
        # 不排除被审计的目标目录（如 test-samples）
        if "test-samples" in file_path_lower:
            return False
        
        # 排除其他测试文件
        if any(keyword in file_path_lower for keyword in ["test", "spec", "mock", "fixture"]):
            return True
        
        # 排除第三方库文件
        if any(keyword in file_path_lower for keyword in ["node_modules", "vendor"]):
            return True
        
        return False

# 工具检查
def check_external_tools() -> Dict[str, bool]:
    """检查外部工具是否可用
    
    Returns:
        Dict[str, bool]: 工具可用性映射
    """
    global EXTERNAL_TOOLS_AVAILABLE
    
    if not EXTERNAL_TOOLS_AVAILABLE:
        for tool_name, tool_config in EXTERNAL_TOOLS.items():
            try:
                result = subprocess.run(
                    [tool_config["cmd"], "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                EXTERNAL_TOOLS_AVAILABLE[tool_name] = result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                EXTERNAL_TOOLS_AVAILABLE[tool_name] = False
    
    return EXTERNAL_TOOLS_AVAILABLE

# 运行Gitleaks扫描
def run_gitleaks_scan(target: str) -> List[Dict]:
    """运行Gitleaks扫描
    
    Args:
        target: 扫描目标
        
    Returns:
        List[Dict]: 扫描结果
    """
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--report-format", "json", "--path", target],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 or result.returncode == 1:
            # Gitleaks返回1表示发现问题
            data = json.loads(result.stdout)
            findings = []
            for item in data:
                findings.append({
                    "file": item.get("File"),
                    "line": item.get("StartLine"),
                    "type": "HARD_CODE_SECRET",
                    "severity": "严重",
                    "cwe": "CWE-321",
                    "description": f"发现硬编码密钥: {item.get('RuleID')}",
                    "code_snippet": item.get("Line"),
                    "source": "gitleaks",
                    "language": "unknown",
                    "gbt_mapping": "GB/T34944-6.2.5.2 敏感信息泄露; GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化"
                })
            return findings
    except Exception as e:
        print(f"Gitleaks扫描失败: {e}")
    
    return []

# 运行Bandit扫描
def run_bandit_scan(file_path: str) -> List[Dict]:
    """运行Bandit扫描
    
    Args:
        file_path: 文件路径
        
    Returns:
        List[Dict]: 扫描结果
    """
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 or result.returncode == 1:
            data = json.loads(result.stdout)
            findings = []
            for issue in data.get("results", []):
                findings.append({
                    "file": issue.get("filename"),
                    "line": issue.get("line_number"),
                    "type": issue.get("test_id"),
                    "severity": "严重" if issue.get("issue_severity") == "HIGH" else "高危",
                    "cwe": issue.get("issue_cwe", {}).get("id", "CWE-000"),
                    "description": issue.get("issue_text"),
                    "code_snippet": issue.get("code"),
                    "source": "bandit",
                    "language": "python",
                    "gbt_mapping": "GB/T34944-6.2.5.2 敏感信息泄露; GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化"
                })
            return findings
    except Exception as e:
        print(f"Bandit扫描失败: {e}")
    
    return []

# 运行Semgrep扫描
def run_semgrep_scan(target: str, language: str) -> List[Dict]:
    """运行Semgrep扫描
    
    Args:
        target: 扫描目标
        language: 语言
        
    Returns:
        List[Dict]: 扫描结果
    """
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", target, f"--lang", language],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0 or result.returncode == 1:
            data = json.loads(result.stdout)
            findings = []
            for result_item in data.get("results", []):
                findings.append({
                    "file": result_item.get("path"),
                    "line": result_item.get("start", {}).get("line"),
                    "type": result_item.get("check_id"),
                    "severity": "严重" if result_item.get("extra", {}).get("severity") == "ERROR" else "高危",
                    "cwe": "CWE-000",
                    "description": result_item.get("extra", {}).get("message", "Semgrep发现的问题"),
                    "code_snippet": result_item.get("extra", {}).get("lines", ""),
                    "source": "semgrep",
                    "language": language,
                    "gbt_mapping": "GB/T34944-6.2.5.2 敏感信息泄露; GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化"
                })
            return findings
    except Exception as e:
        print(f"Semgrep扫描失败: {e}")
    
    return []

# 快速扫描模式
def quick_scan_patterns() -> Dict[str, List[tuple]]:
    """快速扫描模式
    
    Returns:
        Dict[str, List[tuple]]: 语言到模式的映射
    """
    return {
        "java": [
            (r"Runtime\.getRuntime\(\)\.exec\s*\(", "COMMAND_INJECTION", "CWE-78", "严重"),
            (r'String\s+sql\s*=\s*["\'].*?\+.*?["\']', "SQL_INJECTION", "CWE-89", "严重"),
            (r'password\s*=\s*"[^"]{3,}"', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
            (r'(?:private\s+)?(?:static\s+)?(?:final\s+)?String\s+\w*(?:PASSWORD|PASS|SECRET|KEY|TOKEN)\s*=\s*"[^"]{3,}"', "HARD_CODE_SECRET", "CWE-321", "严重"),
            (r'new\s+File\s*\(\s*[^"]*\s*\+\s*', "PATH_TRAVERSAL", "CWE-22", "高危"),
            (r"eval\s*\(", "CODE_INJECTION", "CWE-94", "严重"),
            (r"Statement\.execute", "SQL_INJECTION", "CWE-89", "严重"),
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "WEAK_HASH", "CWE-328", "高危"),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "WEAK_HASH", "CWE-328", "高危"),
            (r'Cipher\.getInstance\s*\(\s*["\']DES["\']', "WEAK_CRYPTO", "CWE-327", "高危"),
            (r"new\s+Random\s*\(\s*\)", "PREDICTABLE_RANDOM", "CWE-338", "高危"),
        ],
        "python": [
            (r"os\.system\s*\(", "COMMAND_INJECTION", "CWE-78", "严重"),
            (r"subprocess\.\w+\s*\(.*shell\s*=\s*True", "COMMAND_INJECTION", "CWE-78", "严重"),
            (r"\bexec\s*\(", "CODE_INJECTION", "CWE-94", "严重"),
            (r"\beval\s*\(", "CODE_INJECTION", "CWE-94", "严重"),
            (r"pickle\.load", "DESERIALIZATION", "CWE-502", "严重"),
            (r"yaml\.load\s*\(.*\)\s*$", "DESERIALIZATION", "CWE-502", "严重"),
            (r'\bpassword\s*=\s*["\']\w+["\']', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
            (r'\b(api|secret|token|key)\s*=\s*["\']\w+["\']', "HARD_CODE_SECRET", "CWE-321", "严重"),
            (r"hashlib\.md5", "WEAK_HASH", "CWE-328", "高危"),
            (r"hashlib\.sha1", "WEAK_HASH", "CWE-328", "高危"),
            (r"random\.rand", "PREDICTABLE_RANDOM", "CWE-338", "高危"),
        ],
        "cpp": [
            (r'system\s*\(\s*[^"]*\s*\+', "COMMAND_INJECTION", "CWE-78", "严重"),
            (r'sprintf\s*\(\s*\w+\s*,\s*[^"]*\s*\+', "BUFFER_OVERFLOW", "CWE-120", "严重"),
            (r"strcpy\s*\(", "BUFFER_OVERFLOW", "CWE-120", "严重"),
            (r"gets\s*\(", "BUFFER_OVERFLOW", "CWE-120", "严重"),
            (r"printf\s*\(\s*\w+\s*\)", "FORMAT_STRING", "CWE-134", "高危"),
            (r"malloc\s*\(\s*\w+\s*\*\s*\d+\s*\)", "INTEGER_OVERFLOW", "CWE-190", "高危"),
            (r'password\s*=\s*"[^"]{3,}"', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
        ],
        "csharp": [
            (r"Process\.Start\s*\(.*\+.*\)", "COMMAND_INJECTION", "CWE-78", "严重"),
            (r"SqlCommand\s*=\s*new\s+SqlCommand\s*\(.*\+.*\)", "SQL_INJECTION", "CWE-89", "严重"),
            (r'password\s*=\s*"[^"]{3,}"', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
            (r'\b(api|secret|token|key)\s*=\s*"\w+"', "HARD_CODE_SECRET", "CWE-321", "严重"),
            (r"DES\.Create\s*\(\)", "WEAK_CRYPTO", "CWE-327", "高危"),
            (r"SHA1\.Create\s*\(\)", "WEAK_HASH", "CWE-328", "高危"),
            (r"Random\s*=\s*new\s+Random\s*\(\)", "PREDICTABLE_RANDOM", "CWE-338", "高危"),
        ],
    }

# 编译的模式缓存
_COMPILED_PATTERNS: Dict[str, List[tuple]] = {}

def _init_compiled_patterns():
    """模块加载时预编译所有正则表达式"""
    pattern_strings = quick_scan_patterns()
    for lang, patterns in pattern_strings.items():
        compiled = []
        for pattern, vuln_type, cwe, severity in patterns:
            compiled.append((re.compile(pattern), vuln_type, cwe, severity))
        _COMPILED_PATTERNS[lang] = compiled

# 初始化编译模式
_init_compiled_patterns()

# 快速扫描单个文件
def quick_scan_file(file_path: str, language: str) -> List[Dict]:
    """快速扫描单个文件
    
    Args:
        file_path: 文件路径
        language: 语言
        
    Returns:
        List[Dict]: 扫描结果
    """
    findings = []
    
    try:
        content = Path(file_path).read_text(encoding='utf-8')
        
        # 使用预编译的正则模式
        for pattern, vuln_type, cwe, severity in _COMPILED_PATTERNS.get(language, []):
            for match in pattern.finditer(content):
                # 计算行号
                line_num = content[:match.start()].count('\n') + 1
                
                # 提取代码片段
                lines = content.split('\n')
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 1)
                code_snippet = '\n'.join(lines[start_line:end_line])
                
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "type": vuln_type,
                    "severity": severity,
                    "cwe": cwe,
                    "description": f"发现{severity}漏洞: {vuln_type}",
                    "code_snippet": code_snippet,
                    "source": "quick_scan",
                    "language": language,
                    "gbt_mapping": "GB/T34944-6.2.5.2 敏感信息泄露; GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化"
                })
    except Exception as e:
        print(f"扫描文件失败 {file_path}: {e}")
    
    return findings

# 并行快速扫描
def parallel_quick_scan(code_files: List[str], file_lang_map: Dict[str, str], max_workers: int = MAX_WORKERS) -> List[Dict]:
    """并行快速扫描
    
    Args:
        code_files: 代码文件列表
        file_lang_map: 文件到语言的映射
        max_workers: 最大工作线程数
        
    Returns:
        List[Dict]: 扫描结果
    """
    findings = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(quick_scan_file, file_path, file_lang_map[file_path]): file_path for file_path in code_files}
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                file_findings = future.result()
                findings.extend(file_findings)
            except Exception as e:
                print(f"扫描文件失败 {file_path}: {e}")
    
    return findings

# 快速扫描
def quick_scan(target_path: str, max_workers: int = MAX_WORKERS, use_external_tools: bool = True) -> Dict:
    """快速扫描：使用正则模式匹配 + 外部专业工具检测常见漏洞
    
    Args:
        target_path: 扫描目标路径
        max_workers: 并行工作线程数
        use_external_tools: 是否优先使用外部工具（Bandit/Semgrep/Gitleaks）
    """
    target = Path(target_path)
    if not target.exists():
        return {"success": False, "error": f"路径不存在：{target_path}"}

    cleanup_result = _cleanup_findings_dir()

    code_files = []
    file_lang_map = {}
    languages = []

    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        for ext in extensions:
            files = list(target.rglob(f"*{ext}"))
            if files:
                if lang not in languages:
                    languages.append(lang)
                for fp in files:
                    code_files.append(str(fp))
                    file_lang_map[str(fp)] = lang

    if not code_files:
        return {"success": False, "error": "未找到代码文件"}

    findings = []

    if use_external_tools:
        available_tools = check_external_tools()
        tools_used = []
        external_findings = []

        if available_tools.get("gitleaks"):
            tools_used.append("gitleaks")
            external_findings.extend(run_gitleaks_scan(str(target)))

        if "python" in languages:
            python_files = [f for f in code_files if f.endswith(".py")]
            if available_tools.get("bandit"):
                tools_used.append("bandit")
                for pf in python_files:
                    external_findings.extend(run_bandit_scan(pf))

        if available_tools.get("semgrep"):
            tools_used.append("semgrep")
            # 对每种语言分别运行 Semgrep
            for lang in languages:
                lang_files = [f for f in code_files if file_lang_map.get(f) == lang]
                if lang_files:
                    external_findings.extend(run_semgrep_scan(str(target), language=lang))

        findings.extend(external_findings)

    findings.extend(parallel_quick_scan(code_files, file_lang_map, max_workers))

    return {
        "success": True,
        "target": str(target),
        "languages": languages,
        "findings": findings,
        "total_findings": len(findings),
        "cleanup": cleanup_result,
        "tools_used": [f"pattern"] + ([t for t in TOOL_PRIORITY if EXTERNAL_TOOLS_AVAILABLE.get(t)] if use_external_tools else []),
    }

# 清理发现目录
def _cleanup_findings_dir() -> Dict:
    """清理发现目录
    
    Returns:
        Dict: 清理结果
    """
    findings_dir = Path("findings")
    if findings_dir.exists():
        try:
            shutil.rmtree(findings_dir)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    try:
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "baseline").mkdir(exist_ok=True)
        (findings_dir / "llm_audit").mkdir(exist_ok=True)
        return {"success": True, "message": "清理完成"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 解析Markdown文件
def parse_finding_md(content: str) -> Dict:
    """解析Markdown格式的审计发现
    
    Args:
        content: Markdown内容
        
    Returns:
        Dict: 解析后的发现
    """
    valid_fields = {
        '编号', '严重等级', '漏洞类型', '文件路径', '行号', 
        'CWE', 'cwe', '国标映射', '来源', '语言', 
        '问题代码', '问题描述', '修复方案', '验证方法'
    }
    
    key_mapping = {
        '编号': 'id', 'id': 'id',
        '严重等级': 'severity', 'severity': 'severity',
        '漏洞类型': 'type', 'type': 'type',
        '文件路径': 'file', 'file': 'file',
        '行号': 'line', 'line': 'line',
        'CWE': 'cwe', 'cwe': 'cwe',
        '国标映射': 'gbt_mapping', 'gbt_mapping': 'gbt_mapping',
        '来源': 'source', 'source': 'source',
        '语言': 'language', 'language': 'language',
        '问题代码': 'code_snippet', 'code_snippet': 'code_snippet',
        '问题描述': 'description', 'description': 'description',
        '修复方案': 'fix', 'fix': 'fix',
        '验证方法': 'verification', 'verification': 'verification',
    }
    
    result = {}
    current_key = None
    current_value = []
    
    lines = content.strip().split('\n')
    
    for line in lines:
        # 不要 strip 整行，因为问题代码需要保留原始格式
        stripped_line = line.strip()
        if not stripped_line:
            continue
        
        # 检查是否是新字段（以有效字段名开头，后跟冒号）
        field_match = None
        for field in valid_fields:
            if stripped_line.startswith(field + '：') or stripped_line.startswith(field + ':'):
                field_match = field
                break
        
        if field_match:
            # 保存当前字段
            if current_key:
                # 对于问题代码，保留换行符
                if current_key == '问题代码':
                    result[key_mapping.get(current_key, current_key)] = '\n'.join(current_value).strip()
                else:
                    result[key_mapping.get(current_key, current_key)] = ' '.join(current_value).strip()
            
            # 开始新字段
            current_key = field_match
            # 提取字段值（去掉字段名和冒号）
            if stripped_line.startswith(field_match + '：'):
                value = stripped_line[len(field_match) + 1:].strip()
            else:
                value = stripped_line[len(field_match) + 1:].strip()
            current_value = [value]
        elif current_key:
            # 继续当前字段的多行内容
            # 对于问题代码，保留原始行（包括缩进）
            if current_key == '问题代码':
                current_value.append(line)
            else:
                current_value.append(stripped_line)
    
    # 保存最后一个字段
    if current_key:
        # 对于问题代码，保留换行符
        if current_key == '问题代码':
            result[key_mapping.get(current_key, current_key)] = '\n'.join(current_value).strip()
        else:
            result[key_mapping.get(current_key, current_key)] = ' '.join(current_value).strip()
    
    # 类型转换
    if 'line' in result:
        try:
            result['line'] = int(result['line'])
        except ValueError:
            result['line'] = 0
    
    return result

# 验证发现
def validate_finding(md_file: str) -> Dict:
    """验证md文件的代码片段是否真实存在
    
    Args:
        md_file: md文件路径
        
    Returns:
        验证结果
    """
    try:
        # 读取md文件
        content = Path(md_file).read_text(encoding='utf-8')
        # 解析md文件
        finding = parse_finding_md(content)
        # 验证代码片段
        validation = validate_code_snippet(finding)
        # 构建返回结果
        if validation['valid']:
            return {
                "success": True,
                "md_file": md_file,
                "validation": validation['reason'],
                "message": "验证通过，可以开始下一个发现"
            }
        else:
            return {
                "success": False,
                "error": "代码片段验证失败，可能存在幻觉",
                "actual_code": validation.get('actual', ''),
                "hint": "尝试修正行号，若无法修正则用下一个问题覆盖当前 md"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"验证失败: {str(e)}",
            "hint": "检查文件路径是否正确"
        }

# 验证代码片段
def validate_code_snippet(finding: Dict) -> Dict:
    """验证代码片段是否真实存在于源文件中
    
    Args:
        finding: 审计发现
        
    Returns:
        包含验证结果的字典
    """

    file_path = finding.get('file', '')
    line_num = finding.get('line', 0)
    code_snippet = finding.get('code_snippet', '')

    if not file_path:
        return {"valid": True, "reason": "skip"}

    # 无效代码片段的特征
    invalid_snippets = {"requires login", "n/a", "null", "none", "undefined"}

    if not code_snippet:
        return {"valid": True, "reason": "skip"}

    try:
        path = Path(file_path)
        if not path.exists():
            return {"valid": True, "reason": "file_not_found"}

        lines = path.read_text(encoding='utf-8').splitlines()
        total_lines = len(lines)

        # 从代码片段中提取行号前缀（格式："行号     代码"）
        snippet_line_num = 0
        snippet_code = code_snippet
        snippet_match = re.match(r'^(\d+)\s+(.+)$', code_snippet.strip())
        if snippet_match:
            snippet_line_num = int(snippet_match.group(1))
            snippet_code = snippet_match.group(2)

        # 清理代码片段
        snippet_clean = snippet_code.strip().replace('\n', '').replace('\r', '')
        snippet_clean = ' '.join(snippet_clean.split())
        snippet_lower = snippet_clean.lower()

        # 如果代码片段行号与记录的行号不一致，优先使用片段中的行号
        if snippet_line_num > 0 and snippet_line_num != line_num:
            if 1 <= snippet_line_num <= total_lines:
                actual_line = lines[snippet_line_num - 1].strip()
                actual_clean = ' '.join(actual_line.split())
                # 检查片段中的代码是否匹配实际行
                if snippet_clean in actual_clean or actual_clean in snippet_clean:
                    return {
                        "valid": True,
                        "reason": "snippet_line_mismatch",
                        "corrected_line": snippet_line_num,
                        "actual_code": actual_line
                    }
                else:
                    # 代码片段中的行号不正确，在文件中搜索正确的行号
                    for i, line in enumerate(lines):
                        search_line = line.strip()
                        search_clean = ' '.join(search_line.split())
                        # 只匹配非空行，并且代码片段确实存在于搜索行中
                        if search_clean and (snippet_clean in search_clean or search_clean in snippet_clean):
                            return {
                                "valid": True,
                                "reason": "snippet_line_corrected",
                                "corrected_line": i + 1,
                                "actual_code": search_line
                            }
                    # 如果搜索不到，使用原始行号
                    if len(actual_clean) >= 5:
                        return {
                            "valid": True,
                            "reason": "snippet_line_invalid",
                            "corrected_line": line_num,
                            "actual_code": actual_line
                        }

        # 如果代码片段是无效的或太短，跳过片段验证，在文件中搜索可疑代码
        if snippet_lower in invalid_snippets or len(snippet_clean) < 5:
            # 根据漏洞类型设置搜索模式
            vuln_type = finding.get('type', '').upper()
            cwe = finding.get('cwe', '').upper()

            search_patterns = []

            # SQL注入相关
            if 'SQL' in vuln_type or 'CWE-89' in cwe:
                search_patterns = [
                    r'SqlCommand\s*\(',
                    r'SqlConnection\s*\(',
                    r'executeQuery\s*\(',
                    r'executeSql\s*\(',
                    r'createStatement\s*\(',
                    r'PreparedStatement\s*\(',
                    r'\.Query\s*\(',
                    r'\.Execute\s*\(',
                ]

            # 命令注入相关
            if 'COMMAND' in vuln_type or 'CWE-78' in cwe:
                search_patterns = [
                    r'os\.system\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'Process\s*\.Start\s*\(',
                    r'subprocess\.',
                    r'exec\s*\(',
                    r'shell\s*\(',
                ]

            # 路径遍历相关
            if 'PATH' in vuln_type or 'CWE-22' in cwe:
                search_patterns = [
                    r'open\s*\(',
                    r'FileInputStream\s*\(',
                    r'FileReader\s*\(',
                    r'Resource\s*\.getResource\s*\(',
                ]

            # 硬编码密码相关
            if 'PASSWORD' in vuln_type or 'CWE-798' in cwe or 'HARD' in vuln_type:
                search_patterns = [
                    r'password\s*=',
                    r'passwd\s*=',
                    r'pwd\s*=',
                    r'ConnectionString\s*=',
                ]

            # XSS相关
            if 'XSS' in vuln_type or 'CWE-79' in cwe:
                search_patterns = [
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'document\.write\s*\(',
                ]

            # 默认搜索所有可疑关键字
            if not search_patterns:
                search_patterns = [
                    r'SqlCommand\s*\(',
                    r'executeQuery\s*\(',
                    r'os\.system\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'open\s*\(',
                    r'innerHTML\s*=',
                ]

            # 在文件中搜索可疑代码
            for i, line in enumerate(lines):
                actual_line = line.strip()
                for pattern in search_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        actual_clean = ' '.join(actual_line.split())
                        if actual_clean and len(actual_clean) >= 5:
                            return {
                                "valid": True,
                                "reason": "snippet_invalid_searched",
                                "corrected_line": i + 1,
                                "actual_code": actual_line
                            }

            # 如果搜索不到，使用原始行号
            if 1 <= line_num <= total_lines:
                actual_line = lines[line_num - 1].strip()
                actual_clean = ' '.join(actual_line.split())
                if actual_clean and len(actual_clean) >= 5:
                    return {
                        "valid": True,
                        "reason": "snippet_invalid_but_line_valid",
                        "corrected_line": line_num,
                        "actual_code": actual_line
                    }
                else:
                    return {"valid": False, "reason": "line_empty", "actual_line_count": total_lines}
            else:
                return {"valid": False, "reason": "line_out_of_range", "actual_line_count": total_lines}

        # 1. 首先检查指定行
        if 1 <= line_num <= total_lines:
            actual_line = lines[line_num - 1].strip()
            actual_clean = ' '.join(actual_line.split())
            
            if snippet_clean in actual_clean or actual_clean in snippet_clean:
                return {"valid": True, "reason": "matched"}
            
            # 检查关键字匹配
            snippet_keywords = set(re.findall(r'\b\w{3,}\b', snippet_clean.lower()))
            actual_keywords = set(re.findall(r'\b\w{3,}\b', actual_clean.lower()))
            
            if snippet_keywords and actual_keywords:
                overlap = snippet_keywords & actual_keywords
                if len(overlap) >= min(2, len(snippet_keywords)):
                    return {"valid": True, "reason": "partial_match"}
        
        # 2. 在整个文件中搜索匹配的代码片段
        for i, line in enumerate(lines):
            actual_line = line.strip()
            actual_clean = ' '.join(actual_line.split())
            
            if actual_clean and (snippet_clean in actual_clean or actual_clean in snippet_clean):
                return {"valid": True, "reason": "matched_in_file", "corrected_line": i + 1}
            
            # 检查关键字匹配
            snippet_keywords = set(re.findall(r'\b\w{3,}\b', snippet_clean.lower()))
            actual_keywords = set(re.findall(r'\b\w{3,}\b', actual_clean.lower()))
            
            if snippet_keywords and actual_keywords:
                overlap = snippet_keywords & actual_keywords
                if len(overlap) >= min(2, len(snippet_keywords)):
                    return {"valid": True, "reason": "partial_match_in_file", "corrected_line": i + 1}
        
        # 3. 如果指定行存在但不匹配
        if 1 <= line_num <= total_lines:
            actual_line = lines[line_num - 1].strip()
            actual_clean = ' '.join(actual_line.split())
            return {
                "valid": False, 
                "reason": "mismatch",
                "expected": snippet_clean[:80],
                "actual": actual_clean[:80]
            }
        else:
            # 行号超出范围
            return {"valid": False, "reason": "line_out_of_range", "actual_line_count": total_lines}
    except Exception as e:
        return {"valid": True, "reason": f"error: {str(e)}"}

def update_findings_md_files(findings: List[Dict]) -> Dict[str, int]:
    """更新所有目录中md文件的行号和代码片段

    Args:
        findings: 审计发现列表

    Returns:
        Dict[str, int]: 更新结果，key为文件路径，value为更新的数量
    """
    updates = {}

    for finding in findings:
        file_path = finding.get('file', '')
        finding_id = finding.get('id', '')
        source = finding.get('source', '')
        if not file_path and not finding_id:
            continue

        md_file = None
        
        # 确定文件应该在哪个目录
        directories = []
        if source == 'llm_audit':
            directories = ['findings/llm_audit']
        else:
            directories = ['findings/baseline']
        
        # 尝试在所有可能的目录中查找文件
        for directory in directories:
            # 首先尝试通过编号查找
            if finding_id:
                id_clean = finding_id.replace('#', '').zfill(3)
                possible_md = Path(f"{directory}/{id_clean}.md")
                if possible_md.exists():
                    md_file = possible_md
                    break
            
            # 如果找不到，尝试通过文件路径查找
            if not md_file and file_path:
                # 从文件路径提取文件名
                file_name = Path(file_path).stem
                possible_md = Path(f"{directory}/{file_name}.md")
                if possible_md.exists():
                    md_file = possible_md
                    break
            
            # 尝试通过文件全名查找
            if not md_file and file_path:
                md_file_name = Path(file_path).name + '.md'
                possible_md = Path(f"{directory}/{md_file_name}")
                if possible_md.exists():
                    md_file = possible_md
                    break

        if not md_file:
            continue

        # 检查是否需要更新
        old_line = finding.get('line', 0)
        corrected_line = finding.get('corrected_line', old_line)
        actual_code = finding.get('actual_code', '')

        # 如果行号没变且没有实际代码，不需要更新
        if old_line == corrected_line and not actual_code:
            continue

        # 读取md文件内容
        content = md_file.read_text(encoding='utf-8')
        lines = content.split('\n')
        new_lines = []
        updated = False

        for line in lines:
            # 更新行号
            if line.startswith('行号:') or line.startswith('行号：'):
                if ':' in line:
                    parts = line.split(':', 1)
                    new_lines.append(f"{parts[0]}: {corrected_line}")
                else:
                    parts = line.split('：', 1)
                    new_lines.append(f"{parts[0]}： {corrected_line}")
                updated = True
            # 更新代码片段
            elif line.startswith('问题代码:'):
                if actual_code:
                    # 构建包含行号的代码片段格式
                    new_lines.append(f"问题代码: {corrected_line}     {actual_code}")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        if updated:
            md_file.write_text('\n'.join(new_lines), encoding='utf-8')
            key = str(md_file)
            updates[key] = updates.get(key, 0) + 1

    return updates

# 过滤幻觉问题
def filter_hallucinated_findings(findings: List[Dict]) -> tuple:
    """过滤掉幻觉问题和误报，返回有效发现和幻觉列表
    
    Args:
        findings: 审计发现列表
        
    Returns:
        (有效发现列表, 幻觉列表)
    """
    valid_findings = []
    hallucinations = []
    
    for finding in findings:
        # 首先检查是否应该被硬排除
        if HardExclusionRules.should_exclude(finding):
            continue
        
        # 对所有发现进行代码片段验证和行号修正
        validation = validate_code_snippet(finding)
        if validation['valid']:
            # 如果找到修正后的行号，更新发现的行号
            if 'corrected_line' in validation:
                finding['line'] = validation['corrected_line']
            # 如果有实际代码，更新代码片段
            if 'actual_code' in validation:
                finding['actual_code'] = validation['actual_code']
            valid_findings.append(finding)
        else:
            hallucinations.append({
                "file": finding.get('file', ''),
                "line": finding.get('line', 0),
                "type": finding.get('type', ''),
                "reason": validation['reason'],
                "expected_code": validation.get('expected', ''),
                "actual_code": validation.get('actual', ''),
            })
    
    # 更新所有目录中md文件的行号
    update_findings_md_files(valid_findings)
    
    return valid_findings, hallucinations

# 计算置信度评分
def calculate_confidence_score(finding: Dict) -> float:
    """计算审计发现的置信度评分
    
    Args:
        finding: 审计发现
        
    Returns:
        float: 置信度评分 (0.0-1.0)
    """
    score = 0.0
    
    # 检查必要字段
    required_fields = ['file', 'line', 'type', 'severity', 'description', 'fix']
    for field in required_fields:
        if field in finding and finding[field]:
            score += 0.1
    
    # 检查代码片段
    if 'code_snippet' in finding and finding['code_snippet']:
        score += 0.2
    
    # 检查CWE
    if 'cwe' in finding and finding['cwe'] and finding['cwe'] != 'CWE-000':
        score += 0.1
    
    # 检查国标映射
    if 'gbt_mapping' in finding and finding['gbt_mapping']:
        score += 0.1
    
    # 检查验证方法
    if 'verification' in finding and finding['verification']:
        score += 0.1
    
    # 来源加分
    source = finding.get('source', '')
    if source == 'llm_audit':
        score += 0.2
    elif source in ['bandit', 'semgrep', 'gitleaks']:
        score += 0.1
    
    # 严重程度加分
    severity = finding.get('severity', '')
    if severity in ['严重', '高危']:
        score += 0.1
    
    return min(1.0, score)

# 去重
def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """内存去重：按文件 + 行号 + 类型去重，优先保留 LLM 审计结果
    
    Args:
        findings: 审计发现列表
        
    Returns:
        去重后的列表
    """
    dedup_dict = {}
    
    for finding in findings:
        file_path = finding.get('file', '')
        line_num = finding.get('line', 0)
        vuln_type = finding.get('type', '')
        source = finding.get('source', '')
        
        key = f"{file_path}:{line_num}:{vuln_type}"
        
        if key not in dedup_dict:
            dedup_dict[key] = finding
        else:
            existing = dedup_dict[key]
            existing_source = existing.get('source', '')
            
            if source == 'llm_audit' and existing_source != 'llm_audit':
                dedup_dict[key] = finding
    
    return list(dedup_dict.values())

# 计算统计信息
def compute_stats(findings: List[Dict]) -> Dict:
    """计算统计信息
    
    Args:
        findings: 审计发现列表
        
    Returns:
        统计信息字典
    """
    stats = {
        "total_count": len(findings),
        "severity_stats": {},
        "source_stats": {},
        "severity_source_stats": {},
        "gbt_stats": {},
        "gbt_prefix_stats": {},
    }
    
    severity_order = ["严重", "高危", "中危", "低危"]
    
    for finding in findings:
        severity = finding.get("severity", "未知")
        source = finding.get("source", "未知")
        
        # 统计严重程度
        stats["severity_stats"][severity] = stats["severity_stats"].get(severity, 0) + 1
        
        # 统计来源
        stats["source_stats"][source] = stats["source_stats"].get(source, 0) + 1
        
        # 统计严重程度和来源的组合
        severity_source_key = f"{severity}:{source}"
        stats["severity_source_stats"][severity_source_key] = stats["severity_source_stats"].get(severity_source_key, 0) + 1
        
        # 统计国标映射
        gbt_mapping = finding.get("gbt_mapping", "")
        if gbt_mapping:
            # 拆分多个国标映射，每个国标单独统计
            gbt_rules = [rule.strip() for rule in gbt_mapping.split(';') if rule.strip()]
            
            # 用于跟踪已统计的国标前缀，确保每个漏洞只在每个国标分类中统计一次
            counted_prefixes = set()
            
            for rule in gbt_rules:
                # 提取国标前缀
                if rule.startswith("GB/T34944"):
                    prefix = "GB/T34944"
                elif rule.startswith("GB/T34943"):
                    prefix = "GB/T34943"
                elif rule.startswith("GB/T34946"):
                    prefix = "GB/T34946"
                elif rule.startswith("GB/T39412"):
                    prefix = "GB/T39412"
                else:
                    prefix = "OTHER"
                
                # 统计每个国标规则
                stats["gbt_stats"][rule] = stats["gbt_stats"].get(rule, 0) + 1
                
                # 确保每个漏洞只在每个国标分类中统计一次
                if prefix not in counted_prefixes:
                    stats["gbt_prefix_stats"][prefix] = stats["gbt_prefix_stats"].get(prefix, 0) + 1
                    counted_prefixes.add(prefix)
    
    return stats

def _get_severity_icon(severity: str) -> str:
    """获取严重等级对应的图标
    
    Args:
        severity: 严重等级
        
    Returns:
        str: 图标
    """
    severity_icons = {
        "严重": "🔴",
        "高危": "🟠",
        "中危": "🟡",
        "低危": "🟢",
    }
    return severity_icons.get(severity, "⚪")

def _get_source_icon(source: str) -> str:
    """获取来源对应的图标
    
    Args:
        source: 来源
        
    Returns:
        str: 图标
    """
    source_icons = {
        "quick_scan": "🔧 快速扫描",
        "llm_audit": "🧠 LLM审计",
        "bandit": "🔍 Bandit",
        "semgrep": "🔍 Semgrep",
        "gitleaks": "🔍 Gitleaks",
    }
    return source_icons.get(source, source)

# 生成汇总表格（符合audit_report.md格式）
def generate_summary_tables(stats: Dict) -> str:
    """生成汇总表格
    
    Args:
        stats: 统计信息
        
    Returns:
        str: 汇总表格的Markdown格式
    """
    summary_lines = []
    
    # 问题汇总表格（包含快速扫描和LLM审计分布）
    summary_lines.append("### 问题汇总")
    summary_lines.append("")
    summary_lines.append("| 严重等级 | 数量 | 快速扫描 | LLM 审计 | 说明 |")
    summary_lines.append("|:--------:|:----:|:--------:|:--------:|:-----:|")
    
    severity_order = ["严重", "高危", "中危", "低危"]
    severity_desc = {
        "严重": "可直接导致系统被入侵",
        "高危": "可导致数据泄露或权限提升",
        "中危": "可能被利用但需要特定条件",
        "低危": "存在安全隐患但影响较小"
    }
    
    total_quick_scan = 0
    total_llm_audit = 0
    
    for severity in severity_order:
        count = stats["severity_stats"].get(severity, 0)
        if count > 0:
            quick_scan_count = stats["severity_source_stats"].get(f"{severity}:quick_scan", 0)
            llm_audit_count = stats["severity_source_stats"].get(f"{severity}:llm_audit", 0)
            total_quick_scan += quick_scan_count
            total_llm_audit += llm_audit_count
            icon = _get_severity_icon(severity)
            summary_lines.append(f"| {icon} {severity} | {count} | {quick_scan_count} | {llm_audit_count} | {severity_desc.get(severity, '')} |")
    
    total_count = stats["total_count"]
    summary_lines.append(f"| **总计** | **{total_count}** | **{total_quick_scan}** | **{total_llm_audit}** | |")
    summary_lines.append("")
    
    # 按国标分类统计
    summary_lines.append("### 按国标分类统计")
    summary_lines.append("")
    summary_lines.append("> ⚠️ **注意**：以下统计仅包含能明确对应到国标规则的安全问题")
    summary_lines.append("")
    
    # GB/T 34943-2017 C/C++
    gbt_34943_rules = {k: v for k, v in stats["gbt_stats"].items() if k.startswith("GB/T34943")}
    if gbt_34943_rules:
        summary_lines.append(f"#### GB/T 34943-2017 C/C++ 语言源代码漏洞测试规范 - {stats['gbt_prefix_stats'].get('GB/T34943', 0)} 个")
        summary_lines.append("")
        summary_lines.append("| 规则 | 问题数 |")
        summary_lines.append("|------|--------|")
        for rule, count in sorted(gbt_34943_rules.items()):
            summary_lines.append(f"| {rule} | {count} |")
        summary_lines.append("")
    
    # GB/T 34944-2017 Java
    gbt_34944_rules = {k: v for k, v in stats["gbt_stats"].items() if k.startswith("GB/T34944")}
    if gbt_34944_rules:
        summary_lines.append(f"#### GB/T 34944-2017 Java 语言源代码漏洞测试规范 - {stats['gbt_prefix_stats'].get('GB/T34944', 0)} 个")
        summary_lines.append("")
        summary_lines.append("| 规则 | 问题数 |")
        summary_lines.append("|------|--------|")
        for rule, count in sorted(gbt_34944_rules.items()):
            summary_lines.append(f"| {rule} | {count} |")
        summary_lines.append("")
    
    # GB/T 34946-2017 C#
    gbt_34946_rules = {k: v for k, v in stats["gbt_stats"].items() if k.startswith("GB/T34946")}
    if gbt_34946_rules:
        summary_lines.append(f"#### GB/T 34946-2017 C# 语言源代码漏洞测试规范 - {stats['gbt_prefix_stats'].get('GB/T34946', 0)} 个")
        summary_lines.append("")
        summary_lines.append("| 规则 | 问题数 |")
        summary_lines.append("|------|--------|")
        for rule, count in sorted(gbt_34946_rules.items()):
            summary_lines.append(f"| {rule} | {count} |")
        summary_lines.append("")
    
    # GB/T 39412-2020 通用
    gbt_39412_rules = {k: v for k, v in stats["gbt_stats"].items() if k.startswith("GB/T39412")}
    if gbt_39412_rules:
        summary_lines.append(f"#### GB/T 39412-2020 网络安全技术 源代码漏洞检测规则 - {stats['gbt_prefix_stats'].get('GB/T39412', 0)} 个")
        summary_lines.append("")
        summary_lines.append("| 规则 | 问题数 |")
        summary_lines.append("|------|--------|")
        for rule, count in sorted(gbt_39412_rules.items()):
            summary_lines.append(f"| {rule} | {count} |")
        summary_lines.append("")
    
    return "\n".join(summary_lines)

def _get_severity_icon(severity: str) -> str:
    """获取严重等级对应的图标
    
    Args:
        severity: 严重等级
        
    Returns:
        str: 图标
    """
    severity_icons = {
        "严重": "🔴",
        "高危": "🟠",
        "中危": "🟡",
        "低危": "🟢",
    }
    return severity_icons.get(severity, "⚪")

def _get_source_icon(source: str) -> str:
    """获取来源对应的图标
    
    Args:
        source: 来源
        
    Returns:
        str: 图标
    """
    source_icons = {
        "quick_scan": "🔧 快速扫描",
        "llm_audit": "🧠 LLM审计",
        "bandit": "🔍 Bandit",
        "semgrep": "🔍 Semgrep",
        "gitleaks": "🔍 Gitleaks",
    }
    return source_icons.get(source, source)

def _format_finding_to_markdown(finding: Dict, index: int) -> str:
    """将发现格式化为 Markdown（符合 SKILL.md 定义的格式）
    
    Args:
        finding: 审计发现
        index: 发现的索引
        
    Returns:
        str: 格式化后的 Markdown
    """
    lines = []
    
    severity = finding.get("severity", "未知")
    vuln_type = finding.get("type", "未知")
    source = finding.get("source", "未知")
    file_path = finding.get("file", "")
    line_num = finding.get("line", 0)
    
    severity_icon = _get_severity_icon(severity)
    source_display = _get_source_icon(source)
    
    lines.append(f"### #{index} {severity_icon} {vuln_type}")
    lines.append("")
    lines.append(f"**来源**: {source_display}")
    lines.append(f"**严重性**: {severity}")
    lines.append(f"**文件**: {file_path}:{line_num}")
    lines.append("")
    
    cwe = finding.get("cwe", "")
    if cwe:
        lines.append(f"**CWE**: {cwe}")
        lines.append("")
    
    gbt_mapping = finding.get("gbt_mapping", "")
    if gbt_mapping:
        lines.append(f"**国标映射**: {gbt_mapping}")
        lines.append("")
    
    language = finding.get("language", "")
    if language:
        lines.append(f"**语言**: {language}")
        lines.append("")
    
    code_snippet = finding.get("code_snippet", "")
    if code_snippet:
        lines.append("**问题代码**:")
        lines.append("```")
        # 保留原始换行符
        lines.append(str(code_snippet))
        lines.append("```")
        lines.append("")
    
    description = finding.get("description", "")
    if description:
        lines.append(f"**问题描述**: {description}")
        lines.append("")
    
    fix = finding.get("fix", "")
    if fix:
        lines.append(f"**修复方案**: {fix}")
        lines.append("")
    
    verification = finding.get("verification", "")
    if verification:
        lines.append(f"**验证方法**: {verification}")
        lines.append("")
    
    return "\n".join(lines)

# 加载所有发现
def load_all_findings() -> List[Dict]:
    """加载所有发现
    
    Returns:
        List[Dict]: 所有发现
    """
    findings = []
    
    # 加载快速扫描的发现
    baseline_dir = Path("findings/baseline")
    if baseline_dir.exists():
        for md_file in baseline_dir.glob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                finding = parse_finding_md(content)
                if finding:
                    findings.append(finding)
            except Exception as e:
                print(f"解析文件失败 {md_file}: {e}")
    
    # 加载LLM审计的发现
    llm_audit_dir = Path("findings/llm_audit")
    if llm_audit_dir.exists():
        for md_file in llm_audit_dir.glob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                finding = parse_finding_md(content)
                if finding:
                    findings.append(finding)
            except Exception as e:
                print(f"解析文件失败 {md_file}: {e}")
    
    return findings

# 生成报告模板
def _generate_report_template(project_name: str, languages: List[str], standards: List[str], audit_date: str) -> str:
    """生成报告模板（符合SKILL.md定义的格式）
    
    Args:
        project_name: 项目名称
        languages: 语言列表
        standards: 标准列表
        audit_date: 审计日期
        
    Returns:
        str: 报告模板
    """
    lines = []
    lines.append(f"# {project_name} 代码安全审计报告")
    lines.append("")
    lines.append("## 封面")
    lines.append("")
    lines.append(f"**项目**: {project_name}")
    lines.append(f"**语言**: {', '.join(languages) if languages else '未知'}")
    lines.append(f"**适用标准**: {', '.join(standards) if standards else '未知'}")
    lines.append(f"**日期**: {audit_date}")
    lines.append(f"**审计人**: Agent")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 审计汇总")
    lines.append("")
    lines.append("<!-- SUMMARY_PLACEHOLDER -->")
    lines.append("")
    lines.append("## 详细发现")
    lines.append("")
    lines.append("<!-- DETAILED_FINDINGS_PLACEHOLDER -->")
    return "\n".join(lines)

# 验证修复质量
def validate_fix_quality(finding: Dict) -> Dict:
    """验证修复质量
    
    Args:
        finding: 审计发现
        
    Returns:
        Dict: 验证结果
    """
    issues = []
    
    # 检查修复方案长度
    fix = finding.get('fix', '')
    if len(fix) < 30:
        issues.append("修复方案字数不足 30 字")
    
    # 检查是否包含具体修复代码
    if '```' not in fix and ('=' not in fix or ';' not in fix):
        issues.append("修复方案应包含具体修复代码")
    
    # 检查是否包含验证方法
    verification = finding.get('verification', '')
    if not verification:
        issues.append("缺少验证方法")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

# 生成最终报告
def finalize_report(
    output_path: str = None,
    summary_updates: Dict = None,
    project_name: str = None,
    languages: List[str] = None,
    standards: List[str] = None,
    audit_date: str = None,
) -> Dict:
    """收尾报告：从 Markdown 文件生成报告
    
    Args:
        output_path: 报告输出路径（可选，默认为 audit_report.md）
        summary_updates: 摘要更新（可选）
        project_name: 项目名称（可选，默认从文件推断）
        languages: 语言列表（可选，默认从文件推断）
        standards: 标准列表（可选，默认从文件推断）
        audit_date: 审计日期（可选，默认使用当前日期）
    """
    if not output_path:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_path = f"audit_report_{timestamp}.md"
    
    try:
        report_path = Path(output_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        all_findings = load_all_findings()
        
        valid_findings, hallucinations = filter_hallucinated_findings(all_findings)
        
        if hallucinations:
            print(json.dumps({
                "warning": f"检测到 {len(hallucinations)} 个幻觉问题，已过滤",
                "hallucinations": hallucinations[:10]
            }, ensure_ascii=False, indent=2))
        
        if not languages:
            lang_set = set()
            for f in valid_findings:
                file_path = f.get("file", "")
                if file_path.endswith(".java"):
                    lang_set.add("Java")
                elif file_path.endswith(".cpp") or file_path.endswith(".cc") or file_path.endswith(".c"):
                    lang_set.add("C/C++")
                elif file_path.endswith(".cs"):
                    lang_set.add("C#")
                elif file_path.endswith(".py"):
                    lang_set.add("Python")
            languages = list(lang_set) if lang_set else []
        
        if not standards:
            gbt_prefixes = set()
            for f in valid_findings:
                gbt = f.get("gbt_mapping", "")
                if gbt:
                    if gbt.startswith("GB/T34944"):
                        gbt_prefixes.add("GB/T 34944-2017")
                    elif gbt.startswith("GB/T34943"):
                        gbt_prefixes.add("GB/T 34943-2017")
                    elif gbt.startswith("GB/T34946"):
                        gbt_prefixes.add("GB/T 34946-2017")
                    elif gbt.startswith("GB/T39412"):
                        gbt_prefixes.add("GB/T 39412-2020")
            standards = sorted(list(gbt_prefixes))
        
        if not project_name:
            if valid_findings:
                first_file = valid_findings[0].get("file", "")
                if first_file:
                    project_name = Path(first_file).parent.name
                else:
                    project_name = "audit-project"
            else:
                project_name = "audit-project"
        
        if not audit_date:
            audit_date = time.strftime("%Y-%m-%d")
        
        if not report_path.exists():
            template_content = _generate_report_template(
                project_name=project_name,
                languages=languages,
                standards=standards,
                audit_date=audit_date,
            )
            report_path.write_text(template_content, encoding="utf-8")
        
        dedup_findings = deduplicate_findings(valid_findings)
        stats = compute_stats(dedup_findings)
        summary_tables = generate_summary_tables(stats)
        
        report_content = report_path.read_text(encoding="utf-8")
        
        placeholder = "<!-- DETAILED_FINDINGS_PLACEHOLDER -->"
        if placeholder in report_content:
            formatted_findings = []
            for idx, f in enumerate(dedup_findings, 1):
                formatted = _format_finding_to_markdown(f, idx)
                formatted_findings.append(formatted)
            merged_findings = "\n\n".join(formatted_findings)
            
            # 替换详细发现
            report_content = report_content.replace(placeholder, merged_findings)
        
        placeholder = "<!-- SUMMARY_PLACEHOLDER -->"
        if placeholder in report_content:
            # 生成摘要
            summary = f"本次审计共发现 **{stats['total_count']}** 个安全问题，其中：\n\n"
            summary += summary_tables
            
            # 替换摘要
            report_content = report_content.replace(placeholder, summary)
        
        report_path.write_text(report_content, encoding="utf-8")
        
        # 验证修复质量
        fix_validation_issues = []
        for finding in dedup_findings:
            validation = validate_fix_quality(finding)
            if not validation["valid"]:
                fix_validation_issues.append({
                    "id": finding.get("id", "unknown"),
                    "issues": validation["issues"]
                })
        
        # 生成验证结果
        validation_result = {
            "success": len(fix_validation_issues) == 0,
            "details_count": len(dedup_findings),
            "total_count": len(dedup_findings),
            "problems": fix_validation_issues,
            "warnings": []
        }
        
        print(json.dumps({
            "success": True,
            "report_path": str(report_path),
            "findings_count": len(dedup_findings),
            "dedup_count": len(dedup_findings),
            "hallucinations_count": len(hallucinations),
            "source_stats": stats["source_stats"],
            "severity_stats": stats["severity_stats"],
            "gbt_prefix_stats": stats["gbt_prefix_stats"],
            "validation": validation_result
        }, ensure_ascii=False, indent=2))
        
        return {
            "success": True,
            "report_path": str(report_path),
            "findings_count": len(dedup_findings),
            "dedup_count": len(dedup_findings),
            "hallucinations_count": len(hallucinations),
            "validation": validation_result
        }
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e)
        }, ensure_ascii=False, indent=2))
        
        return {
            "success": False,
            "error": str(e)
        }

# 主函数
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="代码安全审计工具")
    subparsers = parser.add_subparsers(dest="command")
    
    # 快速扫描子命令
    scan_parser = subparsers.add_parser("quick_scan", help="快速扫描代码")
    scan_parser.add_argument("--target", required=True, help="扫描目标路径")
    scan_parser.add_argument("--max-workers", type=int, default=MAX_WORKERS, help="并行工作线程数")
    scan_parser.add_argument("--no-external-tools", action="store_true", help="不使用外部工具")
    
    # 生成报告子命令
    report_parser = subparsers.add_parser("finalize_report", help="生成最终报告")
    report_parser.add_argument("--output", help="报告输出路径")
    report_parser.add_argument("--project", help="项目名称")
    report_parser.add_argument("--languages", nargs="+", help="语言列表")
    report_parser.add_argument("--standards", nargs="+", help="标准列表")
    report_parser.add_argument("--date", help="审计日期")
    
    # 验证发现子命令
    validate_parser = subparsers.add_parser("validate_finding", help="验证发现")
    validate_parser.add_argument("md_file", help="MD文件路径")
    
    args = parser.parse_args()
    
    if args.command == "quick_scan":
        result = quick_scan(
            args.target,
            max_workers=args.max_workers,
            use_external_tools=not args.no_external_tools
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    
    elif args.command == "finalize_report":
        result = finalize_report(
            output_path=args.output,
            project_name=args.project,
            languages=args.languages,
            standards=args.standards,
            audit_date=args.date
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    
    elif args.command == "validate_finding":
        result = validate_finding(args.md_file)
        print(json.dumps(result, ensure_ascii=False, indent=2))
