#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码安全审计技能 - Markdown文件直接处理方案

流程：快速扫描 → 创建md文件 → LLM审计创建md文件 → finalize_report遍历md文件去重生成报告
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List
import concurrent.futures

MAX_WORKERS = min(os.cpu_count() or 4, 8)

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

LANGUAGE_EXTENSIONS = {
    "java": [".java"],
    "cpp": [".cpp", ".cc", ".cxx", ".c++", ".c"],
    "csharp": [".cs"],
    "python": [".py"],
}


def parse_finding_md(md_content: str) -> Dict:
    """解析Markdown格式的审计发现文件
    
    Args:
        md_content: Markdown文件内容
        
    Returns:
        解析后的字典数据
    """
    finding = {}
    lines = md_content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 同时支持英文冒号 : (0x3a) 和中文冒号：(0xff1a)
        if ':' in line or '\uff1a' in line:
            sep = ':' if ':' in line else '\uff1a'
            key, value = line.split(sep, 1)
            key = key.strip().lower()
            value = value.strip()
        else:
            continue
        
        key_mapping = {
            '编号': 'id', 'id': 'id',
            '严重等级': 'severity', 'severity': 'severity',
            '漏洞类型': 'type', 'type': 'type',
            '文件路径': 'file', 'file': 'file',
            '行号': 'line', 'line': 'line',
            'cwe': 'cwe',
            '国标映射': 'gbt_mapping', 'gbt_mapping': 'gbt_mapping',
            '来源': 'source', 'source': 'source',
            '语言': 'language', 'language': 'language',
            '问题代码': 'code_snippet', 'code_snippet': 'code_snippet',
            '问题描述': 'description', 'description': 'description',
            '修复方案': 'fix', 'fix': 'fix',
            '验证方法': 'verification', 'verification': 'verification',
        }
        
        mapped_key = key_mapping.get(key, key)
        
        if mapped_key == 'line':
            try:
                finding[mapped_key] = int(value)
            except:
                finding[mapped_key] = 0
        else:
            finding[mapped_key] = value
    
    return finding


def load_all_findings(findings_dir: str = "findings") -> List[Dict]:
    """从 findings 目录加载所有 Markdown 文件
    
    Args:
        findings_dir: findings 目录路径
        
    Returns:
        所有审计发现的列表
    """
    findings = []
    findings_path = Path(findings_dir)
    
    if not findings_path.exists():
        return findings
    
    for md_file in findings_path.rglob("*.md"):
        try:
            content = md_file.read_text(encoding='utf-8')
            finding = parse_finding_md(content)
            if finding:
                finding['_md_file'] = str(md_file)
                findings.append(finding)
        except Exception:
            pass
    
    return findings


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
    
    if not file_path or not code_snippet:
        return {"valid": True, "reason": "skip"}
    
    try:
        path = Path(file_path)
        if not path.exists():
            return {"valid": True, "reason": "file_not_found"}
        
        lines = path.read_text(encoding='utf-8').splitlines()
        
        if line_num <= 0 or line_num > len(lines):
            return {"valid": False, "reason": "line_out_of_range", "actual_line_count": len(lines)}
        
        actual_line = lines[line_num - 1].strip()
        
        snippet_clean = code_snippet.strip().replace('\\n', '').replace('\\r', '')
        snippet_clean = ' '.join(snippet_clean.split())
        
        actual_clean = ' '.join(actual_line.split())
        
        if snippet_clean in actual_clean or actual_clean in snippet_clean:
            return {"valid": True, "reason": "matched"}
        
        snippet_keywords = set(re.findall(r'\b\w{3,}\b', snippet_clean.lower()))
        actual_keywords = set(re.findall(r'\b\w{3,}\b', actual_clean.lower()))
        
        if snippet_keywords and actual_keywords:
            overlap = snippet_keywords & actual_keywords
            if len(overlap) >= min(2, len(snippet_keywords)):
                return {"valid": True, "reason": "partial_match"}
        
        return {
            "valid": False, 
            "reason": "mismatch",
            "expected": snippet_clean[:80],
            "actual": actual_clean[:80]
        }
    except Exception as e:
        return {"valid": True, "reason": f"error: {str(e)}"}


def filter_hallucinated_findings(findings: List[Dict]) -> tuple:
    """过滤掉幻觉问题，返回有效发现和幻觉列表
    
    Args:
        findings: 审计发现列表
        
    Returns:
        (有效发现列表, 幻觉列表)
    """
    valid_findings = []
    hallucinations = []
    
    for finding in findings:
        source = finding.get('source', '')
        
        if source == 'quick_scan':
            valid_findings.append(finding)
        else:
            validation = validate_code_snippet(finding)
            if validation['valid']:
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
    
    return valid_findings, hallucinations


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
        severity = finding.get("severity", "中危")
        source = finding.get("source", "unknown")
        gbt_mapping = finding.get("gbt_mapping", "")
        
        stats["severity_stats"][severity] = stats["severity_stats"].get(severity, 0) + 1
        stats["source_stats"][source] = stats["source_stats"].get(source, 0) + 1
        
        if severity not in stats["severity_source_stats"]:
            stats["severity_source_stats"][severity] = {}
        stats["severity_source_stats"][severity][source] = \
            stats["severity_source_stats"][severity].get(source, 0) + 1
        
        if gbt_mapping:
            stats["gbt_stats"][gbt_mapping] = stats["gbt_stats"].get(gbt_mapping, 0) + 1
            
            if gbt_mapping.startswith("GB/T34944"):
                prefix = "GB/T34944"
            elif gbt_mapping.startswith("GB/T34943"):
                prefix = "GB/T34943"
            elif gbt_mapping.startswith("GB/T34946"):
                prefix = "GB/T34946"
            elif gbt_mapping.startswith("GB/T39412"):
                prefix = "GB/T39412"
            else:
                prefix = "OTHER"
            
            stats["gbt_prefix_stats"][prefix] = stats["gbt_prefix_stats"].get(prefix, 0) + 1
    
    return stats


def generate_summary_tables(stats: Dict) -> str:
    """生成汇总表格
    
    Args:
        stats: 统计信息
        
    Returns:
        Markdown 格式的汇总表格
    """
    severity_order = ["严重", "高危", "中危", "低危"]
    severity_icons = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🟢"}
    
    total_count = stats["total_count"]
    severity_stats = stats["severity_stats"]
    source_stats = stats["source_stats"]
    severity_source_stats = stats["severity_source_stats"]
    gbt_stats = stats["gbt_stats"]
    gbt_prefix_stats = stats["gbt_prefix_stats"]
    
    quick_scan_count = source_stats.get("quick_scan", 0)
    llm_audit_count = source_stats.get("llm_audit", 0)
    
    summary_lines = []
    summary_lines.append("## 审计汇总")
    summary_lines.append("")
    summary_lines.append("### 问题汇总")
    summary_lines.append("")
    summary_lines.append("| 严重等级 | 数量 | 快速扫描 | LLM 审计 | 说明 |")
    summary_lines.append("|:--------:|-----:|:--------:|:-------:|------|")
    
    descriptions = {
        "严重": "可直接导致系统被入侵",
        "高危": "可导致数据泄露或权限提升",
        "中危": "可能被利用但需要特定条件",
        "低危": "存在安全隐患但影响较小",
    }
    
    for severity in severity_order:
        count = severity_stats.get(severity, 0)
        qs_count = severity_source_stats.get(severity, {}).get("quick_scan", 0)
        llm_count = severity_source_stats.get(severity, {}).get("llm_audit", 0)
        icon = severity_icons[severity]
        summary_lines.append(
            f"| {icon} {severity} | {count} | {qs_count} | {llm_count} | {descriptions[severity]} |"
        )
    
    summary_lines.append(
        f"| **总计** | **{total_count}** | **{quick_scan_count}** | **{llm_audit_count}** | |"
    )
    summary_lines.append("")
    summary_lines.append(
        f"**总发现**：{total_count} 个（快速扫描发现{quick_scan_count}个，LLM审计发现{llm_audit_count}个）"
    )
    summary_lines.append("")
    summary_lines.append("### 按国标分类统计")
    summary_lines.append("")
    summary_lines.append(
        "> ⚠️ **注意**：以下统计仅包含能明确对应到国标规则的安全问题"
    )
    summary_lines.append("")
    
    prefix_names = {
        "GB/T34944": "GB/T 34944-2017 Java 语言源代码漏洞测试规范",
        "GB/T34943": "GB/T 34943-2017 C/C++ 语言源代码漏洞测试规范",
        "GB/T34946": "GB/T 34946-2017 C# 语言源代码漏洞测试规范",
        "GB/T39412": "GB/T 39412-2020 网络安全技术 源代码漏洞检测规则",
    }
    
    for prefix, count in sorted(gbt_prefix_stats.items()):
        title = prefix_names.get(prefix, prefix)
        summary_lines.append(f"#### {title} - {count} 个")
        summary_lines.append("")
        summary_lines.append("| 规则 | 问题数 |")
        summary_lines.append("|------|--------|")
        
        for rule, rule_count in sorted(gbt_stats.items()):
            if rule.startswith(prefix):
                summary_lines.append(f"| {rule} | {rule_count} |")
        
        summary_lines.append(f"| **合计** | **{count}** |")
        summary_lines.append("")
    
    return "\n".join(summary_lines)


def _format_finding_to_markdown(data: Dict, idx: int) -> str:
    """将解析数据格式化为 Markdown 详细条目"""
    severity_icons = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🟢"}
    source_icons = {"llm_audit": "🤖 LLM 审计", "quick_scan": "🔧 快速扫描"}
    
    severity = data.get("severity", "中危")
    icon = severity_icons.get(severity, "🟡")
    source = data.get("source", "unknown")
    source_label = source_icons.get(source, source)
    
    lines = []
    lines.append(f"### #{idx} {icon} {data.get('type', 'UNKNOWN')}")
    lines.append("")
    lines.append(f"**来源**: {source_label}")
    lines.append("")
    lines.append(f"**严重性**: {severity}")
    lines.append("")
    lines.append(f"**文件**: {data.get('file', '')}:{data.get('line', 0)}")
    lines.append("")
    lines.append(f"**标准**: {data.get('gbt_mapping', 'N/A')}")
    lines.append("")
    lines.append(f"**CWE**: [{data.get('cwe', 'N/A')}](https://cwe.mitre.org/data/definitions/{data.get('cwe', '0').split('-')[-1]}.html)")
    lines.append("")
    lines.append("#### 问题描述")
    lines.append("")
    lines.append(data.get('description', ''))
    lines.append("")
    lines.append("#### 问题代码")
    lines.append("")
    lines.append("```")
    lines.append(data.get('code_snippet', ''))
    lines.append("```")
    lines.append("")
    lines.append("#### 修复方案")
    lines.append("")
    lines.append(data.get('fix', ''))
    lines.append("")
    lines.append("#### 验证方法")
    lines.append("")
    lines.append(data.get('verification', ''))
    lines.append("")
    
    return "\n".join(lines)


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
            report_content = report_content.replace(placeholder, merged_findings)
        
        summary_placeholder = "<!-- SUMMARY_TABLES_PLACEHOLDER -->"
        if summary_placeholder in report_content:
            report_content = report_content.replace(summary_placeholder, summary_tables)
        else:
            pattern = r"## 审计汇总.*?(?=\n---\n\n## 详细发现)"
            report_content = re.sub(
                pattern, summary_tables + "\n\n---\n\n", report_content, flags=re.DOTALL
            )
        
        report_content = report_content.rstrip() + "\n"
        report_path.write_text(report_content, encoding="utf-8")
        
        validation_result = validate_report(output_path)
        
        quick_scan_count = stats["source_stats"].get("quick_scan", 0)
        llm_audit_count = stats["source_stats"].get("llm_audit", 0)
        
        if validation_result.get("success", False):
            findings_dir = Path("findings")
            if findings_dir.exists():
                import shutil
                shutil.rmtree(findings_dir)
                findings_dir.mkdir(parents=True, exist_ok=True)
                (findings_dir / "baseline").mkdir(exist_ok=True)
                (findings_dir / "llm_audit").mkdir(exist_ok=True)
        
        return {
            "success": True,
            "output_path": output_path,
            "total_findings": stats["total_count"],
            "dedup_count": len(dedup_findings),
            "hallucination_count": len(hallucinations),
            "source_stats": stats["source_stats"],
            "severity_stats": stats["severity_stats"],
            "severity_source_stats": stats["severity_source_stats"],
            "gbt_stats": stats["gbt_stats"],
            "gbt_totals": stats["gbt_prefix_stats"],
            "validation": validation_result,
            "findings_cleaned": validation_result.get("success", False),
            "status": "finalized",
        }
    except Exception as e:
        return {"success": False, "error": f"报告收尾失败：{e}"}


def _generate_report_template(project_name: str, languages: List[str], standards: List[str], audit_date: str) -> str:
    """生成报告模板"""
    return f"""# 代码安全审计报告

## 封面
**项目**：{project_name}
**语言**：{', '.join(languages)}
**适用标准**：{', '.join(standards)}
**日期**：{audit_date}
**审计人**：Agent

---

## 审计汇总

<!-- SUMMARY_TABLES_PLACEHOLDER -->

---

## 详细发现

<!-- DETAILED_FINDINGS_PLACEHOLDER -->
"""


def validate_report(report_path: str) -> Dict:
    """验证报告完整性"""
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        issues = []
        warnings = []
        
        omission_phrases = [
            "篇幅限制",
            "仅展示前",
            "按相同格式列出",
            "此处省略",
            "未完待续",
            "部分展示",
        ]
        for phrase in omission_phrases:
            if phrase in content:
                issues.append(f"报告包含省略表述：'{phrase}'")
        
        detailed_entries = re.findall(r"### #(\d+)", content)
        detailed_count = len(detailed_entries)
        
        total_match = re.search(r"\*\*总发现\*\*：(\d+) 个", content)
        total_count = int(total_match.group(1)) if total_match else None
        
        if total_count and detailed_count < total_count:
            issues.append(f"详细条目数 ({detailed_count}) < 总发现数 ({total_count})")
        
        return {
            "success": len(issues) == 0,
            "detailed_count": detailed_count,
            "total_count": total_count,
            "issues": issues,
            "warnings": warnings,
        }
    except Exception as e:
        return {"success": False, "error": f"验证失败：{e}"}


def quick_scan_patterns() -> Dict[str, List[tuple]]:
    """返回预编译的正则模式"""
    return _COMPILED_PATTERNS


def get_gbt_mapping(vuln_type: str, language: str) -> str:
    """根据漏洞类型和语言返回国标映射
    
    Args:
        vuln_type: 漏洞类型（英文）
        language: 编程语言（java/cpp/csharp/python）
        
    Returns:
        国标映射字符串（专用标准 + 通用基线）
    """
    # 漏洞类型到国标规则的映射
    vuln_to_gbt = {
        "COMMAND_INJECTION": {
            "java": "GB/T34944-6.2.3.3 命令注入; GB/T39412-6.1.1.6 命令行注入",
            "cpp": "GB/T34943-6.2.3.3 命令注入; GB/T39412-6.1.1.6 命令行注入",
            "csharp": "GB/T34946-6.2.3.3 命令注入; GB/T39412-6.1.1.6 命令行注入",
            "python": "GB/T39412-6.1.1.6 命令行注入",
        },
        "SQL_INJECTION": {
            "java": "GB/T34944-6.2.3.4 SQL 注入; GB/T39412-8.3.2 SQL 注入",
            "cpp": "GB/T34943-6.2.3.4 SQL 注入; GB/T39412-8.3.2 SQL 注入",
            "csharp": "GB/T34946-6.2.3.4 SQL 注入; GB/T39412-8.3.2 SQL 注入",
            "python": "GB/T39412-8.3.2 SQL 注入",
        },
        "CODE_INJECTION": {
            "java": "GB/T34944-6.2.3.5 代码注入; GB/T39412-7.3.6 暴露危险的方法或函数",
            "cpp": "GB/T39412-7.3.6 暴露危险的方法或函数",
            "csharp": "GB/T34946-6.2.3.5 代码注入; GB/T39412-7.3.6 暴露危险的方法或函数",
            "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
        },
        "PATH_TRAVERSAL": {
            "java": "GB/T34944-6.2.3.1 相对路径遍历; GB/T39412-6.1.1.14 边界值检查缺失",
            "cpp": "GB/T34943-6.2.3.1 相对路径遍历; GB/T39412-6.1.1.14 边界值检查缺失",
            "csharp": "GB/T34946-6.2.3.1 相对路径遍历; GB/T39412-6.1.1.14 边界值检查缺失",
            "python": "GB/T39412-6.1.1.14 边界值检查缺失",
        },
        "HARD_CODE_PASSWORD": {
            "java": "GB/T34944-6.2.6.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "cpp": "GB/T34943-6.2.7.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "csharp": "GB/T34946-6.2.6.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
        },
        "HARD_CODE_SECRET": {
            "java": "GB/T34944-6.2.6.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "cpp": "GB/T34943-6.2.7.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "csharp": "GB/T34946-6.2.6.3 口令硬编码; GB/T39412-6.2.1.3 使用安全相关的硬编码",
            "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
        },
        "WEAK_HASH": {
            "java": "GB/T34944-6.2.6.8 可逆的散列算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "cpp": "GB/T34943-6.2.7.6 可逆的散列算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "csharp": "GB/T34946-6.2.6.8 可逆的散列算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        },
        "WEAK_CRYPTO": {
            "java": "GB/T34944-6.2.6.7 使用已破解或危险的加密算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "cpp": "GB/T34943-6.2.7.5 使用已破解或危险的加密算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "csharp": "GB/T34946-6.2.6.7 使用已破解或危险的加密算法; GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
            "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        },
        "PREDICTABLE_RANDOM": {
            "java": "GB/T34944-6.2.6.10 不充分的随机数; GB/T39412-6.2.1.2 随机数安全",
            "cpp": "GB/T34943-6.2.7.8 不充分的随机数; GB/T39412-6.2.1.2 随机数安全",
            "csharp": "GB/T34946-6.2.6.10 不充分的随机数; GB/T39412-6.2.1.2 随机数安全",
            "python": "GB/T39412-6.2.1.2 随机数安全",
        },
        "BUFFER_OVERFLOW": {
            "java": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
            "cpp": "GB/T34943-6.2.3.6 缓冲区溢出; GB/T39412-8.2.6 内存缓冲区边界操作越界",
            "csharp": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
            "python": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
        },
        "FORMAT_STRING": {
            "java": "GB/T39412-7.3.6 暴露危险的方法或函数",
            "cpp": "GB/T34943-6.2.3.7 格式化字符串漏洞; GB/T39412-7.3.6 暴露危险的方法或函数",
            "csharp": "GB/T39412-7.3.6 暴露危险的方法或函数",
            "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
        },
        "INTEGER_OVERFLOW": {
            "java": "GB/T39412-6.1.1.12 数值赋值越界",
            "cpp": "GB/T34943-6.2.3.8 整数溢出; GB/T39412-6.1.1.12 数值赋值越界",
            "csharp": "GB/T39412-6.1.1.12 数值赋值越界",
            "python": "GB/T39412-6.1.1.12 数值赋值越界",
        },
        "DESERIALIZATION": {
            "java": "GB/T39412-7.1.2 反序列化",
            "cpp": "GB/T39412-7.1.2 反序列化",
            "csharp": "GB/T39412-7.1.2 反序列化",
            "python": "GB/T39412-7.1.2 反序列化",
        },
    }
    
    lang_map = {"java": "java", "cpp": "cpp", "csharp": "csharp", "python": "python", "c": "cpp"}
    lang = lang_map.get(language.lower(), "python")
    
    if vuln_type in vuln_to_gbt:
        return vuln_to_gbt[vuln_type].get(lang, vuln_to_gbt[vuln_type].get("python", ""))
    
    # 默认返回通用基线
    return "GB/T39412-7.3.6 暴露危险的方法或函数"


def quick_scan_file(file_path: str, language: str) -> List[Dict]:
    """快速扫描单个文件"""
    findings = []
    path = Path(file_path)
    
    if not path.exists():
        return findings
    
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        patterns = _COMPILED_PATTERNS.get(language, [])
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            for pattern, vuln_type, cwe, severity in patterns:
                if pattern.search(line):
                    findings.append({
                        "file": str(path),
                        "line": line_num,
                        "type": vuln_type,
                        "cwe": cwe,
                        "severity": severity,
                        "source": "quick_scan",
                        "language": language,
                        "code_snippet": line_stripped if line_stripped else "",
                        "gbt_mapping": get_gbt_mapping(vuln_type, language),
                    })
                    break
    except Exception:
        pass
    
    return findings


def parallel_quick_scan(file_paths: List[str], languages: Dict[str, str], max_workers: int = MAX_WORKERS) -> List[Dict]:
    """并行扫描多个文件"""
    if not file_paths:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(
            lambda fp: quick_scan_file(fp, languages.get(fp, "java")), file_paths
        )
    return [finding for result in results for finding in result]


def quick_scan(target_path: str, max_workers: int = MAX_WORKERS) -> Dict:
    """快速扫描：使用正则模式匹配检测常见漏洞"""
    target = Path(target_path)
    if not target.exists():
        return {"success": False, "error": f"路径不存在：{target_path}"}
    
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
    
    findings = parallel_quick_scan(code_files, file_lang_map, max_workers)
    
    return {
        "success": True,
        "target": str(target),
        "languages": languages,
        "findings": findings,
        "total_findings": len(findings),
    }


_COMPILED_PATTERNS: Dict[str, List[tuple]] = {}


def _init_compiled_patterns():
    """模块加载时预编译所有正则表达式"""
    pattern_strings = {
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
            (r'Process\.Start\s*\(\s*[^"]*\s*\+', "COMMAND_INJECTION", "CWE-78", "严重"),
            (r'String\s+sql\s*=\s*["\'].*?\+.*?["\']', "SQL_INJECTION", "CWE-89", "严重"),
            (r'password\s*=\s*"[^"]{3,}"', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
            (r'File\.ReadAllText\s*\(\s*[^"]*\s*\+\s*', "PATH_TRAVERSAL", "CWE-22", "高危"),
            (r"eval\s*\(", "CODE_INJECTION", "CWE-94", "严重"),
            (r"SHA1\.Create", "WEAK_HASH", "CWE-328", "高危"),
            (r"DES\.Create", "WEAK_CRYPTO", "CWE-327", "高危"),
        ],
        "python": [
            (r'os\.system\s*\(\s*[^"]*\s*\+', "COMMAND_INJECTION", "CWE-78", "严重"),
            (r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "COMMAND_INJECTION", "CWE-78", "严重"),
            (r"exec\s*\(", "CODE_INJECTION", "CWE-95", "严重"),
            (r"eval\s*\(", "CODE_INJECTION", "CWE-95", "严重"),
            (r"pickle\.loads?\s*\(", "DESERIALIZATION", "CWE-502", "严重"),
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "HARD_CODE_PASSWORD", "CWE-259", "严重"),
            (r'(?:API_KEY|SECRET_KEY|TOKEN)\s*=\s*["\'][^"\']{3,}["\']', "HARD_CODE_SECRET", "CWE-321", "严重"),
            (r"hashlib\.md5", "WEAK_HASH", "CWE-328", "高危"),
            (r"random\.random", "PREDICTABLE_RANDOM", "CWE-338", "高危"),
        ],
    }
    for lang, patterns in pattern_strings.items():
        _COMPILED_PATTERNS[lang] = [
            (re.compile(pattern, re.IGNORECASE), vuln_type, cwe, severity)
            for pattern, vuln_type, cwe, severity in patterns
        ]


_init_compiled_patterns()


def main():
    if len(sys.argv) < 2:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": "缺少命令参数",
                    "usage": "python skill.py <command> [args]",
                    "commands": [
                        "quick_scan <target_path>",
                        "extract_code <file_path> <line_number> [--context=3]",
                        "validate_finding <md_file_path>",
                        "finalize_report [--output=报告路径] [--project=名称] [--languages=列表] [--standards=列表] [--date=日期]",
                    ],
                },
                ensure_ascii=False,
            )
        )
        return
    
    command = sys.argv[1]
    
    if command == "quick_scan":
        if len(sys.argv) < 3:
            print(json.dumps({"success": False, "error": "缺少 target 参数"}, ensure_ascii=False))
            return
        result = quick_scan(target_path=sys.argv[2])
        print(json.dumps(result, ensure_ascii=False, indent=2))
    
    elif command == "finalize_report":
        output_path = None
        summary_updates = None
        project_name = None
        languages = None
        standards = None
        audit_date = None
        
        args = sys.argv[2:]
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in ("--output", "-o"):
                if i + 1 < len(args):
                    output_path = args[i + 1]
                    i += 2
                    continue
            elif arg.startswith("--output="):
                output_path = arg.split("=", 1)[1]
            
            elif arg in ("--project", "--project_name", "-p"):
                if i + 1 < len(args):
                    project_name = args[i + 1]
                    i += 2
                    continue
            elif arg.startswith("--project=") or arg.startswith("--project_name="):
                project_name = arg.split("=", 1)[1]
            
            elif arg in ("--languages", "-l"):
                if i + 1 < len(args):
                    languages = args[i + 1].split(",")
                    i += 2
                    continue
            elif arg.startswith("--languages="):
                languages = arg.split("=", 1)[1].split(",")
            
            elif arg in ("--standards", "-s"):
                if i + 1 < len(args):
                    standards = args[i + 1].split(",")
                    i += 2
                    continue
            elif arg.startswith("--standards="):
                standards = arg.split("=", 1)[1].split(",")
            
            elif arg in ("--date", "--audit_date", "-d"):
                if i + 1 < len(args):
                    audit_date = args[i + 1]
                    i += 2
                    continue
            elif arg.startswith("--date=") or arg.startswith("--audit_date="):
                audit_date = arg.split("=", 1)[1]
            
            elif arg.endswith(".json"):
                try:
                    summary_updates = json.loads(Path(arg).read_text(encoding="utf-8"))
                except:
                    pass
            
            elif not arg.startswith("-"):
                output_path = arg
            
            i += 1
        
        result = finalize_report(
            output_path,
            summary_updates,
            project_name,
            languages,
            standards,
            audit_date,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    
    elif command == "extract_code":
        if len(sys.argv) < 4:
            print(json.dumps({
                "success": False, 
                "error": "缺少参数",
                "usage": "python skill.py extract_code <file_path> <line_number> [--context=3]"
            }, ensure_ascii=False))
            return
        
        file_path = sys.argv[2]
        try:
            line_num = int(sys.argv[3])
        except ValueError:
            print(json.dumps({"success": False, "error": "行号必须是整数"}, ensure_ascii=False))
            return
        
        context = 3
        for arg in sys.argv[4:]:
            if arg.startswith("--context="):
                context = int(arg.split("=", 1)[1])
        
        try:
            path = Path(file_path)
            if not path.exists():
                print(json.dumps({"success": False, "error": f"文件不存在：{file_path}"}, ensure_ascii=False))
                return
            
            lines = path.read_text(encoding='utf-8').splitlines()
            
            if line_num <= 0 or line_num > len(lines):
                print(json.dumps({
                    "success": False, 
                    "error": f"行号超出范围，文件共 {len(lines)} 行"
                }, ensure_ascii=False))
                return
            
            start = max(1, line_num - context)
            end = min(len(lines), line_num + context)
            
            result_lines = []
            for i in range(start, end + 1):
                prefix = ">>> " if i == line_num else "    "
                result_lines.append(f"{prefix}{i}: {lines[i-1]}")
            
            print(json.dumps({
                "success": True,
                "file": file_path,
                "line": line_num,
                "code_snippet": lines[line_num - 1].strip(),
                "context": "\n".join(result_lines),
                "total_lines": len(lines)
            }, ensure_ascii=False, indent=2))
        except Exception as e:
            print(json.dumps({"success": False, "error": f"读取文件失败：{e}"}, ensure_ascii=False))
    
    elif command == "validate_finding":
        if len(sys.argv) < 3:
            print(json.dumps({
                "success": False,
                "error": "缺少参数",
                "usage": "python skill.py validate_finding <md_file_path>",
                "example": "python skill.py validate_finding findings/llm_audit/001.md",
                "workflow": [
                    "1. LLM创建md文件",
                    "2. 调用 validate_finding 验证",
                    "3. 验证失败 → 用下一个问题覆盖当前md → 再次验证",
                    "4. 验证成功 → 编号+1，开始下一个md文件"
                ]
            }, ensure_ascii=False, indent=2))
            return
        
        md_path = Path(sys.argv[2])
        
        if not md_path.exists():
            print(json.dumps({"success": False, "error": f"文件不存在：{md_path}"}, ensure_ascii=False))
            return
        
        try:
            content = md_path.read_text(encoding='utf-8')
        except Exception as e:
            print(json.dumps({"success": False, "error": f"读取文件失败：{e}"}, ensure_ascii=False))
            return
        
        finding_data = {}
        for line in content.split('\n'):
            # 同时支持英文冒号 : (0x3a) 和中文冒号：(0xff1a)
            # 优先使用中文冒号分割（避免代码示例中的英文冒号干扰）
            if '\uff1a' in line:
                sep = '\uff1a'
            elif ':' in line:
                sep = ':'
            else:
                continue
            
            key, _, value = line.partition(sep)
            key = key.strip()
            value = value.strip()
            if key == '编号':
                finding_data['id'] = value
            elif key == '严重等级':
                finding_data['severity'] = value
            elif key == '漏洞类型':
                finding_data['type'] = value
            elif key == '文件路径':
                finding_data['file'] = value
            elif key == '行号':
                try:
                    finding_data['line'] = int(value)
                except:
                    finding_data['line'] = 0
            elif key == 'CWE':
                finding_data['cwe'] = value
            elif key == '国标映射':
                finding_data['gbt_mapping'] = value
            elif key == '来源':
                finding_data['source'] = value
            elif key == '语言':
                finding_data['language'] = value
            elif key == '问题代码':
                finding_data['code_snippet'] = value
            elif key == '问题描述':
                finding_data['description'] = value
            elif key == '修复方案':
                finding_data['fix'] = value
            elif key == '验证方法':
                finding_data['verification'] = value
        
        required_fields = ['file', 'line', 'code_snippet', 'type', 'severity', 'source']
        missing = [f for f in required_fields if not finding_data.get(f)]
        if missing:
            print(json.dumps({
                "success": False,
                "error": f"md 文件缺少必填字段：{missing}",
                "hint": "请确保 md 文件包含：文件路径、行号、问题代码、漏洞类型、严重等级、来源"
            }, ensure_ascii=False, indent=2))
            return
        
        # 修复方案质量检查（2026-04-18 新增 - 防止敷衍）
        fix = finding_data.get('fix', '')
        invalid_phrases = ["根据国标", "修复内容", "消除安全隐患", "加强", "进行过滤", "使用安全"]
        if len(fix) < 30:
            print(json.dumps({
                "success": False,
                "error": f"修复方案字数不足 30 字（当前{len(fix)}字），必须提供可执行的具体代码或步骤",
                "current_fix": fix[:50],
                "hint": "修复方案必须包含具体代码、命令、API 名称或配置参数，参考 SKILL.md 中的修复方案示例库"
            }, ensure_ascii=False, indent=2))
            return
        if any(phrase in fix for phrase in invalid_phrases):
            bad_phrase = next(p for p in invalid_phrases if p in fix)
            print(json.dumps({
                "success": False,
                "error": f"修复方案包含敷衍内容 '{bad_phrase}'，必须提供具体代码、命令或配置",
                "current_fix": fix[:80],
                "hint": "禁止使用'根据国标''消除隐患''加强''进行'等敷衍词汇，必须提供可执行的技术方案"
            }, ensure_ascii=False, indent=2))
            return
        if not any(kw in fix for kw in ["()", "=", ":", "替代", "使用", "改为", "移", "配置"]):
            print(json.dumps({
                "success": False,
                "error": "修复方案未包含具体代码或 API，必须提供可执行的技术方案",
                "current_fix": fix[:80],
                "hint": "修复方案应包含代码示例（如 PreparedStatement）、命令（如 chmod 600）、API（如 BCrypt.hashpw）或配置参数"
            }, ensure_ascii=False, indent=2))
            return
        
        source = finding_data.get('source', 'llm_audit')
        if source not in ['quick_scan', 'llm_audit']:
            source = 'llm_audit'
        
        validation = validate_code_snippet(finding_data)
        
        if not validation['valid']:
            print(json.dumps({
                "success": False,
                "error": "代码片段验证失败，可能存在幻觉",
                "reason": validation['reason'],
                "md_file": str(md_path),
                "source_file": finding_data.get('file'),
                "line": finding_data.get('line'),
                "expected_code": validation.get('expected', ''),
                "actual_code": validation.get('actual', ''),
                "hint": "用下一个问题覆盖当前md文件内容后再次验证",
                "action": "覆盖当前md → 再次调用 validate_finding"
            }, ensure_ascii=False, indent=2))
            return
        
        print(json.dumps({
            "success": True,
            "md_file": str(md_path),
            "finding_id": finding_data.get('id'),
            "validation": validation['reason'],
            "message": "验证通过，可以开始下一个发现"
        }, ensure_ascii=False, indent=2))
    
    else:
        print(json.dumps({"success": False, "error": f"未知命令：{command}"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
