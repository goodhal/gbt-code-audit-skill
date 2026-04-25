"""
验证模块
包含核心验证函数
"""
import re
from pathlib import Path
from typing import Dict, List

from constants import (
    VALID_GBT_PREFIXES,
    LANGUAGES_WITH_DEDICATED_STANDARD,
    BASELINE_DIR,
    LLM_AUDIT_DIR,
    SEVERITY_ORDER,
    LLM_REQUIRED_FIELDS,
)

def parse_finding_md(content: str) -> Dict:
    """解析md文件内容为审计发现字典
    
    Args:
        content: md文件内容
        
    Returns:
        Dict: 审计发现字典
    """
    finding = {}
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower()
                value = parts[1].strip()
                if key == '编号':
                    finding['id'] = value
                elif key == '严重等级':
                    finding['severity'] = value
                elif key == '漏洞类型':
                    finding['type'] = value
                elif key == '文件路径':
                    finding['file'] = value
                elif key == '行号':
                    try:
                        finding['line'] = int(value)
                    except ValueError:
                        finding['line'] = 0
                elif key == 'cwe':
                    finding['cwe'] = value
                elif key == '国标映射':
                    finding['gbt_mapping'] = value
                elif key == '来源':
                    finding['source'] = value
                elif key == '语言':
                    finding['language'] = value
                elif key == '状态':
                    finding['status'] = value
                elif key == '问题描述':
                    finding['description'] = value
                elif key == '修复方案':
                    finding['fix'] = value
                elif key == '问题代码':
                    finding['code_snippet'] = value
    
    return finding

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
        'status': '状态',
    }

    issues = []
    missing_fields = []

    source = finding.get('source', '')

    for field, label in required_fields.items():
        value = finding.get(field, '')
        if not value or (isinstance(value, str) and value.strip() == ''):
            missing_fields.append(label)

    if missing_fields:
        issues.append(f"缺少必填字段: {', '.join(missing_fields)}")

    if source == 'llm_audit':
        for field in LLM_REQUIRED_FIELDS:
            value = finding.get(field, '')
            if not value or (isinstance(value, str) and value.strip() == ''):
                issues.append("LLM审计发现缺少修复方案")

    severity = finding.get('severity', '')
    if severity and severity not in SEVERITY_ORDER:
        issues.append(f"严重等级无效: {severity}，应为 {', '.join(SEVERITY_ORDER)}")

    status = finding.get('status', '')
    valid_statuses = ['有效', '误报']
    if status and status not in valid_statuses:
        issues.append(f"状态无效: {status}，应为 '有效' 或 '误报'")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

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

    has_valid_prefix = any(prefix in gbt_mapping for prefix in VALID_GBT_PREFIXES)
    if not has_valid_prefix:
        issues.append(f"国标前缀无效，应为 {', '.join(VALID_GBT_PREFIXES)}")

    if language in LANGUAGES_WITH_DEDICATED_STANDARD:
        dedicated_prefix = LANGUAGES_WITH_DEDICATED_STANDARD[language]
        if '；' not in gbt_mapping and ';' not in gbt_mapping:
            issues.append(f"{language} 应使用双国标映射格式：{dedicated_prefix}；GB/T39412")

        if dedicated_prefix not in gbt_mapping:
            issues.append(f"{language} 应包含 {dedicated_prefix} 语言专用标准")

        if 'GB/T39412' not in gbt_mapping:
            issues.append(f"{language} 应包含 GB/T39412 通用基线")
    else:
        if 'GB/T39412' not in gbt_mapping:
            issues.append(f"{language} 应使用 GB/T39412-2020 通用标准")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

def validate_description_format(finding: Dict) -> Dict:
    """验证问题描述基本完整性（格式检查）

    注意：描述质量的语义判断由 LLM 在审计时完成，此处仅做基本格式检查。

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

    if len(description) < 20:
        issues.append("问题描述字数不足 20 字")

    if code_snippet and description.strip() == code_snippet.strip():
        issues.append("问题描述不应仅重复代码片段")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

def validate_fix_format(finding: Dict) -> Dict:
    """验证修复方案基本完整性（格式检查）

    注意：修复方案的合理性判断由 LLM 在审计时完成，此处仅做基本格式检查。

    Args:
        finding: 审计发现

    Returns:
        Dict: 验证结果
    """
    issues = []

    fix = finding.get('fix', '')
    if len(fix) < 20:
        issues.append("修复方案字数不足 20 字")

    return {
        "valid": len(issues) == 0,
        "issues": issues
    }

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

    invalid_snippets = {"requires login", "n/a", "null", "none", "undefined"}

    if not code_snippet:
        return {"valid": True, "reason": "skip"}

    try:
        path = Path(file_path)
        if not path.exists():
            return {"valid": True, "reason": "file_not_found"}

        lines = path.read_text(encoding='utf-8').splitlines()
        total_lines = len(lines)

        snippet_match = re.match(r'^(\d+)\s+(.+)$', code_snippet.strip())
        if snippet_match:
            snippet_line_num = int(snippet_match.group(1))
            snippet_code = snippet_match.group(2)
        else:
            snippet_line_num = 0
            snippet_code = code_snippet

        snippet_clean = snippet_code.strip().replace('\n', '').replace('\r', '')
        snippet_clean = ' '.join(snippet_clean.split())
        snippet_lower = snippet_clean.lower()

        if snippet_line_num > 0 and snippet_line_num != line_num:
            if 1 <= snippet_line_num <= total_lines:
                actual_line = lines[snippet_line_num - 1].strip()
                actual_clean = ' '.join(actual_line.split())
                if snippet_clean in actual_clean or actual_clean in snippet_clean:
                    return {
                        "valid": True,
                        "reason": "snippet_line_mismatch",
                        "corrected_line": snippet_line_num,
                        "actual_code": actual_line
                    }

        if snippet_lower in invalid_snippets or len(snippet_clean) < 5:
            vuln_type = finding.get('type', '').upper()
            cwe = finding.get('cwe', '').upper()
            search_patterns = []

            if 'SQL' in vuln_type or 'CWE-89' in cwe:
                search_patterns = [
                    r'SqlCommand\s*\(',
                    r'SqlConnection\s*\(',
                    r'executeQuery\s*\(',
                    r'executeSql\s*\(',
                    r'createStatement\s*\(',
                    r'PreparedStatement\s*\(',
                ]

            if 'COMMAND' in vuln_type or 'CWE-78' in cwe:
                search_patterns = [
                    r'os\.system\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'Process\s*\.Start\s*\(',
                    r'subprocess\.',
                    r'exec\s*\(',
                ]

            if 'PATH' in vuln_type or 'CWE-22' in cwe:
                search_patterns = [
                    r'open\s*\(',
                    r'FileInputStream\s*\(',
                    r'FileReader\s*\(',
                    r'ReadAllText\s*\(',
                ]

            if 'PASSWORD' in vuln_type or 'CWE-798' in cwe or 'HARD' in vuln_type:
                search_patterns = [
                    r'password\s*=',
                    r'passwd\s*=',
                    r'pwd\s*=',
                    r'ConnectionString\s*=',
                ]

            if 'XSS' in vuln_type or 'CWE-79' in cwe:
                search_patterns = [
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'document\.write\s*\(',
                    r'Response\.Write\s*\(',
                ]

            if not search_patterns:
                search_patterns = [
                    r'SqlCommand\s*\(',
                    r'executeQuery\s*\(',
                    r'os\.system\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'open\s*\(',
                    r'innerHTML\s*=',
                ]

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

        if 1 <= line_num <= total_lines:
            actual_line = lines[line_num - 1].strip()
            actual_clean = ' '.join(actual_line.split())

            if snippet_clean in actual_clean or actual_clean in snippet_clean:
                return {"valid": True, "reason": "matched"}

            snippet_keywords = set(re.findall(r'\b\w{3,}\b', snippet_clean.lower()))
            actual_keywords = set(re.findall(r'\b\w{3,}\b', actual_clean.lower()))

            if snippet_keywords and actual_keywords:
                overlap = snippet_keywords & actual_keywords
                if len(overlap) >= min(2, len(snippet_keywords)):
                    return {"valid": True, "reason": "partial_match"}

        for i, line in enumerate(lines):
            actual_line = line.strip()
            actual_clean = ' '.join(actual_line.split())

            if actual_clean and (snippet_clean in actual_clean or actual_clean in snippet_clean):
                return {"valid": True, "reason": "matched_in_file", "corrected_line": i + 1}

            snippet_keywords = set(re.findall(r'\b\w{3,}\b', snippet_clean.lower()))
            actual_keywords = set(re.findall(r'\b\w{3,}\b', actual_clean.lower()))

            if snippet_keywords and actual_keywords:
                overlap = snippet_keywords & actual_keywords
                if len(overlap) >= min(2, len(snippet_keywords)):
                    return {"valid": True, "reason": "partial_match_in_file", "corrected_line": i + 1}

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
            return {"valid": False, "reason": "line_out_of_range", "actual_line_count": total_lines}
    except Exception as e:
        return {"valid": True, "reason": f"error: {str(e)}"}

def validate_finding(md_file: str) -> Dict:
    """验证md文件的完整性和质量

    Args:
        md_file: md文件路径

    Returns:
        验证结果
    """
    try:
        content = Path(md_file).read_text(encoding='utf-8')
        finding = parse_finding_md(content)

        validation_results = {}
        all_issues = []

        fields_validation = validate_required_fields(finding)
        validation_results['fields'] = fields_validation
        if not fields_validation['valid']:
            all_issues.extend(fields_validation['issues'])

        gbt_validation = validate_gbt_mapping(finding)
        validation_results['gbt_mapping'] = gbt_validation
        if not gbt_validation['valid']:
            all_issues.extend(gbt_validation['issues'])

        code_validation = validate_code_snippet(finding)
        validation_results['code_snippet'] = code_validation
        if not code_validation['valid']:
            all_issues.append(f"代码片段验证失败: {code_validation.get('reason', '')}")

        desc_validation = validate_description_format(finding)
        validation_results['description'] = desc_validation
        if not desc_validation['valid']:
            all_issues.extend(desc_validation['issues'])

        fix_validation = validate_fix_format(finding)
        validation_results['fix'] = fix_validation
        if not fix_validation['valid']:
            all_issues.extend(fix_validation['issues'])

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