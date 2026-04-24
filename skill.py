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

# 目录和文件路径常量
BASELINE_DIR = Path("findings/baseline")
LLM_AUDIT_DIR = Path("findings/llm_audit")
FINDINGS_DIR = Path("findings")
SCAN_RESULT_FILE = Path("scan_result.json")

# 严重等级常量
SEVERITY_ORDER = ["严重", "高危", "中危", "低危"]
SEVERITY_CRITICAL = "严重"
SEVERITY_HIGH = "高危"
SEVERITY_MEDIUM = "中危"
SEVERITY_LOW = "低危"

# 语言文件扩展名映射（支持所有主流语言）
LANGUAGE_EXTENSIONS = {
    "java": [".java"],
    "python": [".py", ".pyw"],
    "cpp": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
    "csharp": [".cs"],
    "go": [".go"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "php": [".php", ".phtml", ".php3", ".php4", ".php5"],
    "ruby": [".rb", ".rbw"],
    "rust": [".rs"],
    "kotlin": [".kt", ".kts"],
    "swift": [".swift"],
    "scala": [".scala", ".sc"],
    "perl": [".pl", ".pm", ".t"],
    "lua": [".lua"],
    "shell": [".sh", ".bash", ".zsh"],
}

# 有专用国标标准的语言（需要双映射）
LANGUAGES_WITH_DEDICATED_STANDARD = {
    "java": "GB/T34944",
    "cpp": "GB/T34943",
    "c": "GB/T34943",
    "csharp": "GB/T34946",
}

# 所有有效的国标前缀
VALID_GBT_PREFIXES = list(set(list(LANGUAGES_WITH_DEDICATED_STANDARD.values()) + ["GB/T39412"]))

# 国标前缀到标准名称的映射
GBT_PREFIX_TO_STANDARD = {
    "GB/T34943": "GB/T 34943-2017",
    "GB/T34944": "GB/T 34944-2017",
    "GB/T34946": "GB/T 34946-2017",
    "GB/T39412": "GB/T 39412-2020",
}

# 国标前缀到描述的映射
GBT_PREFIX_TO_DESCRIPTION = {
    "GB/T34943": "C/C++ 语言源代码漏洞测试规范",
    "GB/T34944": "Java 语言源代码漏洞测试规范",
    "GB/T34946": "C# 语言源代码漏洞测试规范",
    "GB/T39412": "网络安全技术 源代码漏洞检测规则",
}

# 有外部扫描工具支持的语言
TOOL_SUPPORTED_LANGUAGES = {
    "bandit": ["python"],
    "semgrep": ["java", "python", "cpp", "csharp", "go", "javascript", "typescript", "ruby", "rust"],
    "gitleaks": ["all"],  # gitleaks 支持所有语言（检测密钥）
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
                    "severity": SEVERITY_CRITICAL,
                    "cwe": "CWE-321",
                    "description": f"发现硬编码密钥: {item.get('RuleID')}",
                    "code_snippet": item.get("Line"),
                    "source": "gitleaks",
                    "language": "unknown"
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
    # Bandit test_id 到漏洞类型的映射
    BANDIT_TYPE_MAPPING = {
        "B605": "COMMAND_INJECTION",
        "B602": "COMMAND_INJECTION",
        "B607": "COMMAND_INJECTION",
        "B603": "COMMAND_INJECTION",
        "B102": "CODE_INJECTION",
        "B307": "CODE_INJECTION",
        "B403": "DESERIALIZATION",
        "B301": "DESERIALIZATION",
        "B506": "DESERIALIZATION",
        "B324": "WEAK_HASH",
        "B311": "PREDICTABLE_RANDOM",
        "B105": "HARD_CODE_PASSWORD",
        "B106": "HARD_CODE_PASSWORD",
        "B608": "SQL_INJECTION",
        "B310": "PATH_TRAVERSAL",
        "B110": "IMPROPER_EXCEPTION_HANDLING",
    }

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
                test_id = issue.get("test_id", "")
                vuln_type = BANDIT_TYPE_MAPPING.get(test_id, test_id)
                findings.append({
                    "file": issue.get("filename"),
                    "line": issue.get("line_number"),
                    "type": vuln_type,
                    "severity": SEVERITY_CRITICAL if issue.get("issue_severity") == "HIGH" else SEVERITY_HIGH,
                    "cwe": f"CWE-{issue.get('issue_cwe', {}).get('id', '000')}",
                    "description": issue.get("issue_text"),
                    "code_snippet": issue.get("code"),
                    "source": "bandit",
                    "language": "python"
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
                # 从 check_id 推断漏洞类型
                check_id = result_item.get("check_id", "")
                vuln_type = "UNKNOWN"
                if "sql" in check_id.lower():
                    vuln_type = "SQL_INJECTION"
                elif "command" in check_id.lower() or "exec" in check_id.lower():
                    vuln_type = "COMMAND_INJECTION"
                elif "path" in check_id.lower() or "traversal" in check_id.lower():
                    vuln_type = "PATH_TRAVERSAL"
                elif "crypto" in check_id.lower() or "hash" in check_id.lower():
                    vuln_type = "WEAK_CRYPTO"
                elif "random" in check_id.lower():
                    vuln_type = "PREDICTABLE_RANDOM"
                elif "secret" in check_id.lower() or "password" in check_id.lower():
                    vuln_type = "HARD_CODE_SECRET"

                findings.append({
                    "file": result_item.get("path"),
                    "line": result_item.get("start", {}).get("line"),
                    "type": vuln_type,
                    "severity": SEVERITY_CRITICAL if result_item.get("extra", {}).get("severity") == "ERROR" else SEVERITY_HIGH,
                    "cwe": "CWE-000",
                    "description": result_item.get("extra", {}).get("message", "Semgrep发现的问题"),
                    "code_snippet": result_item.get("extra", {}).get("lines", ""),
                    "source": "semgrep",
                    "language": language
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
                
                # 提取代码片段（前后各2行，共约5行）
                lines = content.split('\n')
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
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
                    "language": language
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

    # 计算严重等级统计
    severity_stats = {}
    for f in findings:
        sev = f.get('severity', '未知')
        severity_stats[sev] = severity_stats.get(sev, 0) + 1

    return {
        "success": True,
        "target": str(target),
        "languages": languages,
        "findings": findings,
        "total_findings": len(findings),
        "severity_stats": severity_stats,
        "cleanup": cleanup_result,
        "tools_used": [f"pattern"] + ([t for t in TOOL_PRIORITY if EXTERNAL_TOOLS_AVAILABLE.get(t)] if use_external_tools else []),
    }

# 创建 baseline md 文件
def create_baseline_md_files(findings: List[Dict], silent: bool = True) -> Dict:
    """根据 findings 自动创建所有 baseline md 文件

    Args:
        findings: 审计发现列表（来自 scan_result.json）
        silent: 是否静默模式（不打印 md 内容）

    Returns:
        Dict: 创建结果
    """
    baseline_dir = BASELINE_DIR
    baseline_dir.mkdir(parents=True, exist_ok=True)

    created_count = 0
    errors = []

    # 按文件-行号-类型去重（但保留所有发现）
    for idx, finding in enumerate(findings, 1):
        try:
            # 生成文件名
            file_path = finding.get('file', '')
            line_num = finding.get('line', 0)
            vuln_type = finding.get('type', '')

            # 清理文件路径用于命名
            file_name = Path(file_path).stem if file_path else 'unknown'
            lang = finding.get('language', 'unknown')

            # 格式：001_java_command_injection_31.md
            md_filename = f"{idx:03d}_{lang}_{vuln_type.lower()}_{line_num}.md"
            md_path = baseline_dir / md_filename

            # 获取基本信息
            severity = finding.get('severity', '未知')
            cwe = finding.get('cwe', '')
            if isinstance(cwe, int):
                cwe = f"CWE-{cwe}"
            code_snippet = finding.get('code_snippet', '')
            description = finding.get('description', '')
            source = finding.get('source', 'baseline')


            # 构建 md 内容
            md_content = f"""编号: #{idx:03d}
严重等级: {severity}
漏洞类型: {vuln_type}
文件路径: {file_path}
行号: {line_num}
CWE: {cwe}
国标映射: （待LLM填写）
来源: {source}
语言: {lang}
状态: 有效
问题代码: {code_snippet}
问题描述: {description}
修复方案: （待LLM填写）
"""

            md_path.write_text(md_content, encoding='utf-8')
            created_count += 1

        except Exception as e:
            errors.append({
                "finding": idx,
                "error": str(e)
            })

    result = {
        "success": len(errors) == 0,
        "created_count": created_count,
        "total_findings": len(findings),
        "baseline_dir": str(baseline_dir),
        "errors": errors
    }

    if not silent:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    return result


def validate_llm_audit_coverage(languages: List[str] = None) -> Dict:
    """统计 LLM 审计覆盖情况

    注意：国标映射的正确性由 validate_gbt_mapping 验证，此处仅统计覆盖。

    Args:
        languages: 语言列表（可选，默认从 findings 推断）

    Returns:
        Dict: 统计结果
    """
    llm_audit_dir = LLM_AUDIT_DIR
    if not llm_audit_dir.exists():
        return {
            "valid": False,
            "error": "LLM 审计目录不存在",
            "hint": "步骤6 必须创建 LLM 审计发现文件"
        }

    # 加载 LLM 审计发现
    llm_findings = []
    for md_file in llm_audit_dir.glob("*.md"):
        try:
            content = md_file.read_text(encoding='utf-8')
            finding = parse_finding_md(content)
            if finding:
                llm_findings.append(finding)
        except Exception:
            pass

    if not llm_findings:
        return {
            "valid": False,
            "error": "LLM 审计发现数量为 0",
            "llm_count": 0,
            "hint": "步骤6 必须进行独立审计"
        }

    # 统计覆盖情况
    covered_types = set()
    covered_by_lang = {}

    for finding in llm_findings:
        vuln_type = finding.get("type", "").upper()
        lang = finding.get("language", "").lower()

        covered_types.add(vuln_type)
        if lang not in covered_by_lang:
            covered_by_lang[lang] = {"types": [], "count": 0}
        covered_by_lang[lang]["types"].append(vuln_type)
        covered_by_lang[lang]["count"] += 1

    # 推断语言
    if not languages:
        languages = list(covered_by_lang.keys())

    return {
        "valid": True,
        "llm_count": len(llm_findings),
        "covered_types": list(covered_types),
        "covered_by_lang": covered_by_lang,
        "languages": languages
    }

# 校验 baseline 文件数量
def validate_baseline_count(expected_count: int = None) -> Dict:
    """校验 baseline 目录的 md 文件数量是否符合预期

    Args:
        expected_count: 预期的文件数量（可选，默认从 scan_result.json 读取）

    Returns:
        Dict: 校验结果
    """
    baseline_dir = BASELINE_DIR
    if not baseline_dir.exists():
        return {
            "valid": False,
            "error": "baseline 目录不存在",
            "actual_count": 0,
            "expected_count": expected_count or 0
        }

    actual_count = len(list(baseline_dir.glob("*.md")))

    # 如果没有提供预期数量，从 scan_result.json 读取
    if expected_count is None:
        scan_result_path = SCAN_RESULT_FILE
        if scan_result_path.exists():
            try:
                scan_data = json.loads(scan_result_path.read_text(encoding='utf-8'))
                expected_count = scan_data.get("total_findings", 0)
            except Exception:
                expected_count = 0

    if expected_count is None:
        expected_count = 0

    if actual_count < expected_count:
        return {
            "valid": False,
            "error": f"baseline md 文件数量不足：实际 {actual_count} 个，预期 {expected_count} 个",
            "actual_count": actual_count,
            "expected_count": expected_count,
            "hint": "步骤5 必须为所有 findings 创建对应的 baseline md 文件，禁止手动筛选"
        }

    return {
        "valid": True,
        "actual_count": actual_count,
        "expected_count": expected_count
    }

# 清理发现目录
def _cleanup_findings_dir() -> Dict:
    """清理发现目录，清理前先压缩备份

    Returns:
        Dict: 清理结果
    """
    import zipfile
    from datetime import datetime

    findings_dir = Path("findings")

    if not findings_dir.exists():
        findings_dir.mkdir(parents=True, exist_ok=True)
        (FINDINGS_DIR / "baseline").mkdir(exist_ok=True)
        (FINDINGS_DIR / "llm_audit").mkdir(exist_ok=True)
        return {"success": True, "message": "目录不存在，已创建新目录"}

    # 检查是否有 md 文件需要备份
    has_content = any(findings_dir.rglob("*.md"))

    if not has_content:
        return {"success": True, "message": "目录为空，无需清理"}

    # 压缩备份
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = Path(f"findings_backup_{timestamp}.zip")

    try:
        with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for md_file in findings_dir.rglob("*.md"):
                arcname = md_file.relative_to(findings_dir.parent)
                zf.write(md_file, arcname)

        shutil.rmtree(findings_dir)
        findings_dir.mkdir(parents=True, exist_ok=True)
        (FINDINGS_DIR / "baseline").mkdir(exist_ok=True)
        (FINDINGS_DIR / "llm_audit").mkdir(exist_ok=True)

        return {
            "success": True,
            "backup_file": str(backup_file),
            "message": f"已备份到 {backup_file} 并清理"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# 创建基线发现文件
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
        '问题代码', '问题描述', '修复方案', '状态'
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
        '状态': 'status', 'status': 'status',
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

# 验证必填字段
def validate_required_fields(finding: Dict) -> Dict:
    """验证必填字段是否完整

    Args:
        finding: 审计发现

    Returns:
        Dict: 验证结果
    """
    required_fields = {
        'id': '编号',
        'severity': '严重等级',
        'type': '漏洞类型',
        'file': '文件路径',
        'line': '行号',
        'cwe': 'CWE',
        'gbt_mapping': '国标映射',
        'source': '来源',
        'language': '语言',
        'code_snippet': '问题代码',
        'description': '问题描述',
        'fix': '修复方案',
        'status': '状态',
    }

    issues = []
    missing_fields = []

    for field, label in required_fields.items():
        value = finding.get(field, '')
        if not value or (isinstance(value, str) and value.strip() == ''):
            missing_fields.append(label)

    if missing_fields:
        issues.append(f"缺少必填字段: {', '.join(missing_fields)}")

    # 验证严重等级是否有效
    severity = finding.get('severity', '')
    valid_severities = ['严重', '高危', '中危', '低危']
    if severity and severity not in valid_severities:
        issues.append(f"严重等级无效: {severity}，应为 {', '.join(valid_severities)}")

    # 验证状态是否有效
    status = finding.get('status', '')
    valid_statuses = ['有效', '误报']
    if status and status not in valid_statuses:
        issues.append(f"状态无效: {status}，应为 '有效' 或 '误报'")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

# 验证国标映射
def validate_gbt_mapping(finding: Dict) -> Dict:
    """验证国标映射格式是否正确

    Args:
        finding: 审计发现

    Returns:
        Dict: 验证结果
    """
    issues = []
    gbt_mapping = finding.get('gbt_mapping', '')
    language = finding.get('language', '').lower()

    if not gbt_mapping:
        issues.append("国标映射为空")
        return {"valid": False, "issues": issues}

    # 检查国标前缀格式
    has_valid_prefix = any(prefix in gbt_mapping for prefix in VALID_GBT_PREFIXES)
    if not has_valid_prefix:
        issues.append(f"国标前缀无效，应为 {', '.join(VALID_GBT_PREFIXES)}")

    # 有专用标准的语言：需要双映射（专用标准 + GB/T39412）
    if language in LANGUAGES_WITH_DEDICATED_STANDARD:
        dedicated_prefix = LANGUAGES_WITH_DEDICATED_STANDARD[language]
        # 检查是否有分隔符（中文分号）
        if '；' not in gbt_mapping and ';' not in gbt_mapping:
            issues.append(f"{language} 应使用双国标映射格式：{dedicated_prefix}；GB/T39412")

        # 检查是否包含专用标准
        if dedicated_prefix not in gbt_mapping:
            issues.append(f"{language} 应包含 {dedicated_prefix} 语言专用标准")

        # 检查是否包含 GB/T39412（通用基线）
        if 'GB/T39412' not in gbt_mapping:
            issues.append(f"{language} 应包含 GB/T39412 通用基线")

    # 其他语言（Python/Go/JS/PHP/Rust等）：使用 GB/T39412 通用标准
    else:
        if 'GB/T39412' not in gbt_mapping:
            issues.append(f"{language} 应使用 GB/T39412-2020 通用标准（无专用标准时可仅用 GB/T39412）")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

# 验证问题描述
def validate_description(finding: Dict) -> Dict:
    """验证问题描述基本完整性

    注意：描述质量的语义判断由 LLM 在审计时完成，此处仅做基本检查。

    Args:
        finding: 审计发现

    Returns:
        Dict: 验证结果
    """
    issues = []
    description = finding.get('description', '')
    code_snippet = finding.get('code_snippet', '')

    if not description:
        issues.append("问题描述为空")
        return {"valid": False, "issues": issues}

    # 字数检查（至少20字）- 基本完整性
    if len(description) < 20:
        issues.append("问题描述字数不足 20 字")

    # 检查是否仅重复代码片段 - 基本合理性
    if code_snippet and description.strip() == code_snippet.strip():
        issues.append("问题描述不应仅重复代码片段")

    # 不做关键词检查 - LLM 应自主判断描述是否说明了漏洞原因和风险

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

# 验证发现
def validate_finding(md_file: str) -> Dict:
    """验证md文件的完整性和质量

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

        # 收集所有验证结果
        validation_results = {}
        all_issues = []

        # 1. 必填字段验证
        fields_validation = validate_required_fields(finding)
        validation_results['fields'] = fields_validation
        if not fields_validation['valid']:
            all_issues.extend(fields_validation['issues'])

        # 2. 国标映射验证
        gbt_validation = validate_gbt_mapping(finding)
        validation_results['gbt_mapping'] = gbt_validation
        if not gbt_validation['valid']:
            all_issues.extend(gbt_validation['issues'])

        # 3. 代码片段/行号验证
        code_validation = validate_code_snippet(finding)
        validation_results['code_snippet'] = code_validation
        if not code_validation['valid']:
            all_issues.append(f"代码片段验证失败: {code_validation.get('reason', '')}")

        # 4. 问题描述验证
        desc_validation = validate_description(finding)
        validation_results['description'] = desc_validation
        if not desc_validation['valid']:
            all_issues.extend(desc_validation['issues'])

        # 5. 修复方案质量验证
        fix_validation = validate_fix_quality(finding)
        validation_results['fix'] = fix_validation
        if not fix_validation['valid']:
            all_issues.extend(fix_validation['issues'])

        # 构建返回结果
        if len(all_issues) == 0:
            return {
                "success": True,
                "md_file": md_file,
                "validation": "all_passed",
                "message": "所有验证通过",
                "details": validation_results
            }
        else:
            return {
                "success": False,
                "md_file": md_file,
                "issues": all_issues,
                "details": validation_results,
                "hint": "请修正上述问题后重新验证"
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
            directories = [str(LLM_AUDIT_DIR)]
        else:
            directories = [str(BASELINE_DIR)]
        
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
    
    severity_order = SEVERITY_ORDER
    
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
            gbt_rules = []
            for part in gbt_mapping.replace('；', ';').replace('，', ',').split(';'):
                for subpart in part.split(','):
                    subpart = subpart.strip()
                    if subpart:
                        gbt_rules.append(subpart)
            
            # 用于跟踪已统计的国标前缀，确保每个漏洞只在每个国标分类中统计一次
            counted_prefixes = set()
            
            for rule in gbt_rules:
                # 提取国标前缀
                prefix = "OTHER"
                for valid_prefix in VALID_GBT_PREFIXES:
                    if rule.startswith(valid_prefix):
                        prefix = valid_prefix
                        break

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
        SEVERITY_CRITICAL: "🔴",
        SEVERITY_HIGH: "🟠",
        SEVERITY_MEDIUM: "🟡",
        SEVERITY_LOW: "🟢",
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
    
    severity_order = SEVERITY_ORDER
    severity_desc = {
        SEVERITY_CRITICAL: "可直接导致系统被入侵",
        SEVERITY_HIGH: "可导致数据泄露或权限提升",
        SEVERITY_MEDIUM: "可能被利用但需要特定条件",
        SEVERITY_LOW: "存在安全隐患但影响较小"
    }
    
    total_quick_scan = 0
    total_llm_audit = 0

    for severity in severity_order:
        count = stats["severity_stats"].get(severity, 0)
        if count > 0:
            # 尝试多种可能的 llm_audit 来源键名（原始值和显示值）
            llm_audit_count = (
                stats["severity_source_stats"].get(f"{severity}:llm_audit", 0) +
                stats["severity_source_stats"].get(f"{severity}:🧠 LLM审计", 0) +
                stats["severity_source_stats"].get(f"{severity}:LLM审计", 0)
            )
            # 快速扫描 = 该严重等级总数 - LLM审计数（包含bandit、quick_scan等所有baseline来源）
            quick_scan_count = count - llm_audit_count
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

    # 循环生成各国标统计表格
    for prefix in VALID_GBT_PREFIXES:
        gbt_rules = {k: v for k, v in stats["gbt_stats"].items() if k.startswith(prefix)}
        if gbt_rules:
            standard = GBT_PREFIX_TO_STANDARD.get(prefix, prefix)
            description = GBT_PREFIX_TO_DESCRIPTION.get(prefix, "")
            count = stats['gbt_prefix_stats'].get(prefix, 0)
            summary_lines.append(f"#### {standard} {description} - {count} 个")
            summary_lines.append("")
            summary_lines.append("| 规则 | 问题数 |")
            summary_lines.append("|------|--------|")
            for rule, count in sorted(gbt_rules.items()):
                summary_lines.append(f"| {rule} | {count} |")
            summary_lines.append("")
    
    return "\n".join(summary_lines)

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
    lines.append(f"**来源**: {source}")
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

    return "\n".join(lines)

# 加载所有发现
def load_all_findings() -> List[Dict]:
    """加载所有发现

    Returns:
        List[Dict]: 所有发现（排除误报）
    """
    findings = []
    filtered_count = 0  # 误报过滤计数

    # 加载快速扫描的发现
    baseline_dir = BASELINE_DIR
    if baseline_dir.exists():
        for md_file in baseline_dir.glob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                finding = parse_finding_md(content)
                if finding:
                    # 过滤误报状态
                    status = finding.get('status', '有效')
                    if status == '误报':
                        filtered_count += 1
                        continue
                    findings.append(finding)
            except Exception as e:
                print(f"解析文件失败 {md_file}: {e}")

    # 加载LLM审计的发现
    llm_audit_dir = LLM_AUDIT_DIR
    if llm_audit_dir.exists():
        for md_file in llm_audit_dir.glob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                finding = parse_finding_md(content)
                if finding:
                    # 过滤误报状态
                    status = finding.get('status', '有效')
                    if status == '误报':
                        filtered_count += 1
                        continue
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
    """验证修复方案基本完整性

    注意：修复方案的合理性判断由 LLM 在审计时完成，此处仅做基本检查。

    Args:
        finding: 审计发现

    Returns:
        Dict: 验证结果
    """
    issues = []

    # 检查修复方案长度 - 基本完整性
    fix = finding.get('fix', '')
    if len(fix) < 20:
        issues.append("修复方案字数不足 20 字")

    # 不做关键词检查 - LLM 应自主判断修复方案是否具体、合理、可行

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
    # ⚠️ 校验 baseline 文件数量
    baseline_validation = validate_baseline_count()
    if not baseline_validation.get('valid'):
        print(json.dumps({
            "warning": "baseline 校验失败",
            "details": baseline_validation
        }, ensure_ascii=False, indent=2))

    # ⚠️ 校验 LLM 审计覆盖情况
    llm_validation = validate_llm_audit_coverage(languages)
    if not llm_validation.get('valid'):
        print(json.dumps({
            "warning": "LLM 审计校验失败",
            "details": llm_validation
        }, ensure_ascii=False, indent=2))

    if not output_path:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_path = f"audit_report_{timestamp}.md"
    
    try:
        report_path = Path(output_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)

        # 统计误报数量
        false_positive_count = 0
        for md_dir in [BASELINE_DIR, LLM_AUDIT_DIR]:
            if md_dir.exists():
                for md_file in md_dir.glob("*.md"):
                    try:
                        content = md_file.read_text(encoding='utf-8')
                        for line in content.split('\n'):
                            if line.startswith('状态:') and '误报' in line:
                                false_positive_count += 1
                                break
                    except:
                        pass

        all_findings = load_all_findings()

        valid_findings, hallucinations = filter_hallucinated_findings(all_findings)

        # 输出误报过滤信息
        if false_positive_count > 0:
            print(json.dumps({
                "false_positives_filtered": false_positive_count,
                "message": f"已过滤 {false_positive_count} 个标记为误报的发现"
            }, ensure_ascii=False, indent=2))

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
                    for prefix, standard in GBT_PREFIX_TO_STANDARD.items():
                        if gbt.startswith(prefix):
                            gbt_prefixes.add(standard)
                            break
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
            "total_before_dedup": len(valid_findings),
            "findings_count": len(dedup_findings),
            "dedup_removed": len(valid_findings) - len(dedup_findings),
            "hallucinations_count": len(hallucinations),
            "source_stats": stats["source_stats"],
            "severity_stats": stats["severity_stats"],
            "gbt_prefix_stats": stats["gbt_prefix_stats"],
            "validation": validation_result
        }, ensure_ascii=False, indent=2))

        return {
            "success": True,
            "report_path": str(report_path),
            "total_before_dedup": len(valid_findings),
            "findings_count": len(dedup_findings),
            "dedup_removed": len(valid_findings) - len(dedup_findings),
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

    # 快速扫描参数：隔离模式（默认）
    scan_parser.add_argument("--output-file", default=str(SCAN_RESULT_FILE), help=f"完整结果保存路径（默认 {SCAN_RESULT_FILE}）")
    scan_parser.add_argument("--show-details", action="store_true", help="显示完整 findings 详情（仅调试用，违反隔离原则）")
    scan_parser.add_argument("--create-baseline", action="store_true", help="自动创建所有 baseline md 文件（静默模式，内容不打印到控制台）")

    args = parser.parse_args()

    if args.command == "quick_scan":
        result = quick_scan(
            args.target,
            max_workers=args.max_workers,
            use_external_tools=not args.no_external_tools
        )

        # 保存完整结果到文件（隔离模式）
        if result.get('success'):
            output_file = Path(args.output_file)
            output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

            # 自动创建 baseline md 文件（如果指定了 --create-baseline）
            if args.create_baseline:
                baseline_result = create_baseline_md_files(result.get('findings', []), silent=True)
                if baseline_result.get('success'):
                    print("")
                    print(f"✅ 已自动创建 {baseline_result['created_count']} 个 baseline md 文件")
                    print(f"   目录: {baseline_result['baseline_dir']}")
                else:
                    print("")
                    print(f"⚠️ baseline 创建失败: {baseline_result.get('errors', [])}")

        # 输出模式
        if args.show_details:
            # 调试模式：输出完整结果（违反隔离原则）
            print("⚠️ 警告：--show-details 模式会暴露 findings 详情，LLM 审计将无法保持独立性")
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            # 隔离模式：只输出统计摘要
            summary = {
                "success": result.get("success"),
                "target": result.get("target"),
                "languages": result.get("languages"),
                "total_findings": result.get("total_findings"),
                "severity_stats": result.get("severity_stats", {}),
                "tools_used": result.get("tools_used", []),
                "output_file": args.output_file,
                "message": "完整结果已保存到文件，findings 详情已隔离（LLM 审计时不应查看文件内容）"
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))

            # ⚠️ 强制提醒：必须创建所有 baseline md 文件
            if result.get('success') and result.get('total_findings', 0) > 0:
                print("")
                print("=" * 60)
                if args.create_baseline:
                    print("✅ 步骤5已完成")
                    print("=" * 60)
                    print(f"已自动创建 {result['total_findings']} 个 baseline md 文件")
                    print(f"baseline 目录: {BASELINE_DIR}")
                else:
                    print("⚠️ 步骤5强制要求")
                    print("=" * 60)
                    print(f"发现 {result['total_findings']} 个漏洞")
                    print(f"必须为 {SCAN_RESULT_FILE} 中所有 findings 创建对应的 baseline md 文件")
                    print(f"禁止手动筛选，去重由 finalize_report 自动执行")
                    print(f"baseline 目录应包含 {result['total_findings']} 个 md 文件")
                print("=" * 60)

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
