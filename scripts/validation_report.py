"""
质检校验模块
用于验证审计发现文件的质量和完整性
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from constants import (
    BASELINE_DIR,
    LLM_AUDIT_DIR,
    SEVERITY_ORDER,
    REQUIRED_FIELDS,
    LLM_REQUIRED_FIELDS,
    VALID_GBT_PREFIXES,
    LANGUAGES_WITH_DEDICATED_STANDARD,
)

def load_finding_file(md_file: Path) -> Optional[Dict]:
    """加载并解析单个发现文件

    Args:
        md_file: MD 文件路径

    Returns:
        Dict or None: 解析后的发现字典
    """
    try:
        content = md_file.read_text(encoding='utf-8')
        return parse_finding_md(content)
    except Exception:
        return None

def parse_finding_md(content: str) -> Dict:
    """解析 MD 文件内容为审计发现字典

    Args:
        content: MD 文件内容

    Returns:
        Dict: 审计发现字典
    """
    result = {}
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

    current_key = None
    current_value = []
    lines = content.strip().split('\n')

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        field_match = None
        for field in valid_fields:
            if stripped_line.startswith(field + '：') or stripped_line.startswith(field + ':'):
                field_match = field
                break

        if field_match:
            if current_key:
                if current_key == '问题代码':
                    result[key_mapping.get(current_key, current_key)] = '\n'.join(current_value).strip()
                else:
                    result[key_mapping.get(current_key, current_key)] = ' '.join(current_value).strip()

            current_key = field_match
            if stripped_line.startswith(field_match + '：'):
                value = stripped_line[len(field_match) + 1:].strip()
            else:
                value = stripped_line[len(field_match) + 1:].strip()
            current_value = [value]
        elif current_key:
            if current_key == '问题代码':
                current_value.append(line)
            else:
                current_value.append(stripped_line)

    if current_key:
        if current_key == '问题代码':
            result[key_mapping.get(current_key, current_key)] = '\n'.join(current_value).strip()
        else:
            result[key_mapping.get(current_key, current_key)] = ' '.join(current_value).strip()

    if 'line' in result:
        try:
            result['line'] = int(result['line'])
        except ValueError:
            result['line'] = 0

    return result

class QualityChecker:
    """审计发现质量检查器"""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.passed_checks: List[str] = []

    def check_required_fields(self, finding: Dict, source: str = "") -> bool:
        """检查必填字段是否完整

        Args:
            finding: 审计发现
            source: 来源（baseline/llm_audit）

        Returns:
            bool: 是否通过检查
        """
        required = {
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
            'status': '状态',
        }

        missing = []
        for field, label in required.items():
            value = finding.get(field, '')
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append(label)

        if missing:
            self.errors.append(f"缺少必填字段: {', '.join(missing)}")
            return False

        self.passed_checks.append("必填字段检查")
        return True

    def check_severity_format(self, finding: Dict) -> bool:
        """检查严重等级格式

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        severity = finding.get('severity', '')
        if severity not in SEVERITY_ORDER:
            self.errors.append(f"严重等级无效: {severity}，应为 {', '.join(SEVERITY_ORDER)}")
            return False

        self.passed_checks.append("严重等级格式检查")
        return True

    def check_status_format(self, finding: Dict) -> bool:
        """检查状态格式

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        status = finding.get('status', '')
        valid_statuses = ['有效', '误报']
        if status not in valid_statuses:
            self.errors.append(f"状态无效: {status}，应为 {', '.join(valid_statuses)}")
            return False

        self.passed_checks.append("状态格式检查")
        return True

    def check_gbt_mapping(self, finding: Dict) -> bool:
        """检查国标映射格式

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        gbt_mapping = finding.get('gbt_mapping', '')
        language = finding.get('language', '').lower()

        if not gbt_mapping:
            self.errors.append("国标映射为空")
            return False

        has_valid_prefix = any(prefix in gbt_mapping for prefix in VALID_GBT_PREFIXES)
        if not has_valid_prefix:
            self.errors.append(f"国标前缀无效，应为 {', '.join(VALID_GBT_PREFIXES)}")
            return False

        if language in LANGUAGES_WITH_DEDICATED_STANDARD:
            dedicated_prefix = LANGUAGES_WITH_DEDICATED_STANDARD[language]
            if '；' not in gbt_mapping and ';' not in gbt_mapping:
                self.errors.append(f"{language} 应使用双国标映射格式：{dedicated_prefix}；GB/T39412")
                return False

            if dedicated_prefix not in gbt_mapping:
                self.errors.append(f"{language} 应包含 {dedicated_prefix} 语言专用标准")
                return False

            if 'GB/T39412' not in gbt_mapping:
                self.errors.append(f"{language} 应包含 GB/T39412 通用基线")
                return False

        self.passed_checks.append("国标映射检查")
        return True

    def check_description_quality(self, finding: Dict) -> bool:
        """检查问题描述质量

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        description = finding.get('description', '')
        code_snippet = finding.get('code_snippet', '')

        if not description:
            self.errors.append("问题描述为空")
            return False

        if len(description) < 20:
            self.warnings.append("问题描述字数不足 20 字")
            return False

        if code_snippet and description.strip() == code_snippet.strip():
            self.warnings.append("问题描述不应仅重复代码片段")
            return False

        self.passed_checks.append("问题描述质量检查")
        return True

    def check_code_snippet(self, finding: Dict) -> bool:
        """检查代码片段有效性

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        file_path = finding.get('file', '')
        line_num = finding.get('line', 0)
        code_snippet = finding.get('code_snippet', '')

        if not file_path:
            return True

        invalid_snippets = {"requires login", "n/a", "null", "none", "undefined"}
        if not code_snippet:
            self.warnings.append("代码片段为空")
            return False

        snippet_lower = code_snippet.strip().lower()
        if snippet_lower in invalid_snippets or len(snippet_lower) < 5:
            self.warnings.append("代码片段疑似无效")
            return False

        return True

    def check_llm_fix_quality(self, finding: Dict) -> bool:
        """检查 LLM 审计的修复方案质量

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        source = finding.get('source', '')
        if source != 'llm_audit':
            return True

        fix = finding.get('fix', '')
        if not fix:
            self.errors.append("LLM 审计发现缺少修复方案")
            return False

        if len(fix) < 20:
            self.warnings.append("修复方案字数不足 20 字")
            return False

        self.passed_checks.append("修复方案质量检查")
        return True

    def check_file_exists(self, finding: Dict) -> bool:
        """检查问题文件是否存在

        Args:
            finding: 审计发现

        Returns:
            bool: 是否通过检查
        """
        file_path = finding.get('file', '')
        if not file_path:
            return True

        path = Path(file_path)
        if not path.exists():
            self.warnings.append(f"源文件不存在: {file_path}")
            return False

        return True

    def check_all(self, finding: Dict, source: str = "") -> Tuple[bool, Dict]:
        """执行所有检查

        Args:
            finding: 审计发现
            source: 来源

        Returns:
            Tuple[bool, Dict]: (是否通过, 检查结果)
        """
        self.errors = []
        self.warnings = []
        self.passed_checks = []

        checks = [
            self.check_required_fields(finding, source),
            self.check_severity_format(finding),
            self.check_status_format(finding),
            self.check_gbt_mapping(finding),
            self.check_description_quality(finding),
            self.check_code_snippet(finding),
            self.check_llm_fix_quality(finding),
            self.check_file_exists(finding),
        ]

        passed = all(checks)
        return passed, {
            "passed": passed,
            "errors": self.errors,
            "warnings": self.warnings,
            "passed_checks": self.passed_checks,
        }

def validate_finding_file(md_file: Path) -> Dict:
    """验证单个发现文件

    Args:
        md_file: MD 文件路径

    Returns:
        Dict: 验证结果
    """
    finding = load_finding_file(md_file)
    if not finding:
        return {
            "file": str(md_file),
            "valid": False,
            "error": "文件解析失败",
        }

    source = finding.get('source', 'baseline')
    checker = QualityChecker()
    passed, result = checker.check_all(finding, source)

    return {
        "file": str(md_file),
        "id": finding.get('id', ''),
        "type": finding.get('type', ''),
        "severity": finding.get('severity', ''),
        "valid": passed,
        **result,
    }

def validate_baseline_files() -> Dict:
    """验证所有 baseline 文件

    Returns:
        Dict: 验证结果汇总
    """
    baseline_dir = BASELINE_DIR
    if not baseline_dir.exists():
        return {
            "valid": False,
            "error": "baseline 目录不存在",
            "total": 0,
            "passed": 0,
            "failed": 0,
        }

    results = []
    passed_count = 0
    failed_count = 0

    for md_file in baseline_dir.glob("*.md"):
        result = validate_finding_file(md_file)
        results.append(result)
        if result.get("valid"):
            passed_count += 1
        else:
            failed_count += 1

    return {
        "valid": failed_count == 0,
        "total": len(results),
        "passed": passed_count,
        "failed": failed_count,
        "details": results,
    }

def validate_llm_audit_files() -> Dict:
    """验证所有 LLM 审计文件

    Returns:
        Dict: 验证结果汇总
    """
    llm_audit_dir = LLM_AUDIT_DIR
    if not llm_audit_dir.exists():
        return {
            "valid": False,
            "error": "llm_audit 目录不存在",
            "total": 0,
            "passed": 0,
            "failed": 0,
        }

    results = []
    passed_count = 0
    failed_count = 0

    for md_file in llm_audit_dir.glob("*.md"):
        result = validate_finding_file(md_file)
        results.append(result)
        if result.get("valid"):
            passed_count += 1
        else:
            failed_count += 1

    return {
        "valid": failed_count == 0,
        "total": len(results),
        "passed": passed_count,
        "failed": failed_count,
        "details": results,
    }

def generate_quality_report(output_path: str = None) -> str:
    """生成质量校验报告

    Args:
        output_path: 报告输出路径

    Returns:
        str: 报告内容
    """
    baseline_results = validate_baseline_files()
    llm_results = validate_llm_audit_files()

    lines = []
    lines.append("# 审计质量校验报告")
    lines.append("")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Baseline 发现校验结果")
    lines.append("")
    if baseline_results["total"] == 0:
        lines.append("未找到 baseline 发现文件")
    else:
        lines.append(f"- 总数: {baseline_results['total']}")
        lines.append(f"- 通过: {baseline_results['passed']}")
        lines.append(f"- 失败: {baseline_results['failed']}")
        lines.append(f"- 状态: {'✅ 全部通过' if baseline_results['valid'] else '❌ 存在不合格项'}")
        lines.append("")

        if not baseline_results['valid']:
            lines.append("### 失败详情")
            lines.append("")
            for detail in baseline_results['details']:
                if not detail.get('valid'):
                    lines.append(f"#### {detail.get('file')}")
                    lines.append(f"- 编号: {detail.get('id', 'N/A')}")
                    lines.append(f"- 类型: {detail.get('type', 'N/A')}")
                    if detail.get('errors'):
                        lines.append(f"- 错误: {', '.join(detail['errors'])}")
                    if detail.get('warnings'):
                        lines.append(f"- 警告: {', '.join(detail['warnings'])}")
                    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## LLM 审计发现校验结果")
    lines.append("")
    if llm_results["total"] == 0:
        lines.append("未找到 LLM 审计发现文件")
    else:
        lines.append(f"- 总数: {llm_results['total']}")
        lines.append(f"- 通过: {llm_results['passed']}")
        lines.append(f"- 失败: {llm_results['failed']}")
        lines.append(f"- 状态: {'✅ 全部通过' if llm_results['valid'] else '❌ 存在不合格项'}")
        lines.append("")

        if not llm_results['valid']:
            lines.append("### 失败详情")
            lines.append("")
            for detail in llm_results['details']:
                if not detail.get('valid'):
                    lines.append(f"#### {detail.get('file')}")
                    lines.append(f"- 编号: {detail.get('id', 'N/A')}")
                    lines.append(f"- 类型: {detail.get('type', 'N/A')}")
                    if detail.get('errors'):
                        lines.append(f"- 错误: {', '.join(detail['errors'])}")
                    if detail.get('warnings'):
                        lines.append(f"- 警告: {', '.join(detail['warnings'])}")
                    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 校验标准")
    lines.append("")
    lines.append("| 检查项 | 说明 |")
    lines.append("|--------|------|")
    lines.append("| 必填字段 | 编号、严重等级、漏洞类型等必须完整 |")
    lines.append("| 严重等级 | 必须为 严重/高危/中危/低危 之一 |")
    lines.append("| 状态 | 必须为 有效/误报 之一 |")
    lines.append("| 国标映射 | 必须符合语言对应的国标格式要求 |")
    lines.append("| 问题描述 | 字数 >= 20，不可仅重复代码 |")
    lines.append("| 代码片段 | 必须真实有效，不可为占位符 |")
    lines.append("| 修复方案 | LLM 审计发现必须包含，字数 >= 20 |")

    report_content = '\n'.join(lines)

    if output_path:
        Path(output_path).write_text(report_content, encoding='utf-8')

    return report_content

def run_quality_check() -> Dict:
    """运行质量检查并输出结果

    Returns:
        Dict: 检查结果
    """
    baseline_results = validate_baseline_files()
    llm_results = validate_llm_audit_files()

    all_passed = baseline_results['valid'] and llm_results['valid']

    result = {
        "success": all_passed,
        "baseline": {
            "total": baseline_results['total'],
            "passed": baseline_results['passed'],
            "failed": baseline_results['failed'],
            "valid": baseline_results['valid'],
        },
        "llm_audit": {
            "total": llm_results['total'],
            "passed": llm_results['passed'],
            "failed": llm_results['failed'],
            "valid": llm_results['valid'],
        },
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if not all_passed:
        failed_items = []
        for detail in baseline_results.get('details', []) + llm_results.get('details', []):
            if not detail.get('valid'):
                failed_items.append({
                    "file": detail.get('file'),
                    "errors": detail.get('errors', []),
                    "warnings": detail.get('warnings', []),
                })

        if failed_items:
            print(json.dumps({
                "warning": "存在不合格项",
                "failed_items": failed_items[:10],
            }, ensure_ascii=False, indent=2))

    return result
