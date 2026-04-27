"""
漏洞评级模块
基于可达性(Reachability)、影响范围(Impact)、利用复杂度(Complexity)三维评分
参考: GB/T 39412-2020 和 CVSS 3.1 标准
"""
from typing import Dict, Tuple, Optional
from dataclasses import dataclass

@dataclass
class CVSSScore:
    """CVSS 评分结果"""
    reachability: int
    impact: int
    complexity: int
    score: float
    cvss: float
    severity: str
    prefix: str

SEVERITY_PREFIX_MAP = {
    "严重": "C",
    "高危": "H",
    "中危": "M",
    "低危": "L",
}

VULN_TYPE_CODES = {
    "COMMAND_INJECTION": "CMD",
    "SQL_INJECTION": "SQL",
    "CODE_INJECTION": "CODE",
    "PATH_TRAVERSAL": "PATH",
    "XSS": "XSS",
    "XXE": "XXE",
    "DESERIALIZATION": "DES",
    "SSRF": "SSRF",
    "OSCI": "OSCI",
    "HARD_CODE_PASSWORD": "PASS",
    "HARD_CODE_SECRET": "SEC",
    "WEAK_HASH": "HASH",
    "WEAK_CRYPTO": "CRYPTO",
    "PREDICTABLE_RANDOM": "RAND",
    "AUTH_BYPASS": "AUTH",
    "INFO_LEAK": "INFO",
    "XPATH_INJECTION": "XPATH",
    "FORMAT_STRING": "FMT",
    "BUFFER_OVERFLOW": "BUF",
    "INTEGER_OVERFLOW": "INT",
    "PROCESS_CONTROL": "PROC",
    "DESERIALIZATION": "DES",
    "FILE_UPLOAD": "UPLOAD",
    "FILE_READ": "READ",
    "OPEN_REDIRECT": "REDIRECT",
    "SESSION_FIXATION": "SESS",
    "COOKIE_MANIPULATION": "COOKIE",
    "CREDENTIAL_EXPOSURE": "CRED",
    "MISSING_AUTH": "NOAUTH",
    "BROKEN_AUTH": "BROKEN",
}

DEFAULT_RATINGS = {
    "COMMAND_INJECTION": (3, 3, 3),
    "SQL_INJECTION": (3, 3, 3),
    "CODE_INJECTION": (3, 3, 3),
    "DESERIALIZATION": (3, 3, 2),
    "SSRF": (3, 2, 2),
    "PATH_TRAVERSAL": (3, 2, 2),
    "XSS": (3, 2, 2),
    "XXE": (3, 3, 2),
    "HARD_CODE_PASSWORD": (3, 2, 3),
    "HARD_CODE_SECRET": (3, 3, 3),
    "WEAK_HASH": (2, 2, 1),
    "WEAK_CRYPTO": (2, 2, 1),
    "PREDICTABLE_RANDOM": (2, 2, 2),
    "AUTH_BYPASS": (3, 3, 2),
    "INFO_LEAK": (2, 1, 1),
    "BUFFER_OVERFLOW": (2, 3, 2),
    "FORMAT_STRING": (3, 2, 3),
    "INTEGER_OVERFLOW": (2, 2, 2),
    "PROCESS_CONTROL": (3, 3, 2),
    "XPath_INJECTION": (3, 2, 2),
    "FILE_UPLOAD": (3, 2, 2),
    "FILE_READ": (3, 2, 2),
    "OPEN_REDIRECT": (2, 1, 3),
    "SESSION_FIXATION": (2, 2, 2),
    "COOKIE_MANIPULATION": (2, 2, 2),
}

def calculate_cvss(reachability: int, impact: int, complexity: int) -> Tuple[float, float, str]:
    """计算 CVSS 评分

    Args:
        reachability: 可达性 (R): 0-3
        impact: 影响范围 (I): 0-3
        complexity: 利用复杂度 (C): 0-3 (反向，越容易分越高)

    Returns:
        Tuple[float, float, str]: (Score, CVSS, 严重等级)
    """
    score = reachability * 0.40 + impact * 0.35 + complexity * 0.25

    cvss = round(score / 3.0 * 10.0, 1)

    if cvss >= 9.0:
        severity = "严重"
    elif cvss >= 7.0:
        severity = "高危"
    elif cvss >= 4.0:
        severity = "中危"
    else:
        severity = "低危"

    return score, cvss, severity

def calculate_from_finding(
    vuln_type: str,
    reachability: Optional[int] = None,
    impact: Optional[int] = None,
    complexity: Optional[int] = None,
    override_severity: Optional[str] = None,
) -> CVSSScore:
    """从漏洞类型和可选参数计算评分

    Args:
        vuln_type: 漏洞类型
        reachability: 可达性 (0-3)，默认从漏洞类型推断
        impact: 影响范围 (0-3)，默认从漏洞类型推断
        complexity: 利用复杂度 (0-3)，默认从漏洞类型推断
        override_severity: 覆盖严重等级

    Returns:
        CVSSScore: 评分结果
    """
    if override_severity:
        severity = override_severity
        r, i, c = DEFAULT_RATINGS.get(vuln_type, (2, 2, 2))
        score, cvss, _ = calculate_cvss(r, i, c)
    else:
        if reachability is None or impact is None or complexity is None:
            default = DEFAULT_RATINGS.get(vuln_type, (2, 2, 2))
            if reachability is None:
                reachability = default[0]
            if impact is None:
                impact = default[1]
            if complexity is None:
                complexity = default[2]

        severity_map = {
            "严重": "严重",
            "高危": "高危",
            "中危": "中危",
            "低危": "低危",
        }
        score, cvss, severity = calculate_cvss(reachability, impact, complexity)
        severity = severity_map.get(severity, severity)

    prefix = SEVERITY_PREFIX_MAP.get(severity, "L")

    return CVSSScore(
        reachability=reachability or DEFAULT_RATINGS.get(vuln_type, (2, 2, 2))[0],
        impact=impact or DEFAULT_RATINGS.get(vuln_type, (2, 2, 2))[1],
        complexity=complexity or DEFAULT_RATINGS.get(vuln_type, (2, 2, 2))[2],
        score=score,
        cvss=cvss,
        severity=severity,
        prefix=prefix,
    )

def generate_vuln_id(vuln_type: str, severity: str, sequence: int) -> str:
    """生成漏洞编号

    Args:
        vuln_type: 漏洞类型
        severity: 严重等级
        sequence: 序号

    Returns:
        str: 漏洞编号，格式: {C/H/M/L}-{TYPE}-{001}
    """
    type_code = VULN_TYPE_CODES.get(vuln_type.upper(), "VULN")
    prefix = SEVERITY_PREFIX_MAP.get(severity, "L")
    return f"{prefix}-{type_code}-{sequence:03d}"

def convert_legacy_severity(severity: str) -> str:
    """将传统严重等级转换为标准严重等级

    Args:
        severity: 传统严重等级（严重/高危/中危/低危）

    Returns:
        str: 标准严重等级
    """
    mapping = {
        "严重": "严重",
        "高危": "高危",
        "中危": "中危",
        "低危": "低危",
    }
    return mapping.get(severity, severity)

def get_severity_description(severity: str) -> str:
    """获取严重等级描述

    Args:
        severity: 严重等级

    Returns:
        str: 描述
    """
    descriptions = {
        "严重": "可直接导致系统沦陷",
        "高危": "可造成重大损害",
        "中危": "可造成一定损害",
        "低危": "安全加固建议",
    }
    return descriptions.get(severity, "未知")

def format_cvss_report(cvss_score: CVSSScore, vuln_type: str) -> str:
    """格式化 CVSS 评分报告

    Args:
        cvss_score: CVSS 评分结果
        vuln_type: 漏洞类型

    Returns:
        str: 格式化的报告
    """
    lines = []
    lines.append("### CVSS 评分详情")
    lines.append("")
    lines.append("| 项目 | 分值 | 说明 |")
    lines.append("|------|------|------|")
    lines.append(f"| 可达性 (R) | {cvss_score.reachability}/3 | {get_reachability_desc(cvss_score.reachability)} |")
    lines.append(f"| 影响范围 (I) | {cvss_score.impact}/3 | {get_impact_desc(cvss_score.impact)} |")
    lines.append(f"| 利用复杂度 (C) | {cvss_score.complexity}/3 | {get_complexity_desc(cvss_score.complexity)} |")
    lines.append(f"| **总分** | **{cvss_score.score:.2f}** | |")
    lines.append(f"| **CVSS 3.1** | **{cvss_score.cvss}** | {cvss_score.severity}级 |")
    lines.append("")
    return '\n'.join(lines)

def get_reachability_desc(r: int) -> str:
    """获取可达性描述"""
    descs = {
        3: "无需认证，HTTP 直接可达",
        2: "需要普通用户认证",
        1: "需要管理员权限或内网访问",
        0: "代码不可达/死代码",
    }
    return descs.get(r, "未知")

def get_impact_desc(i: int) -> str:
    """获取影响范围描述"""
    descs = {
        3: "RCE/任意文件写入/完全数据泄露",
        2: "敏感数据泄露/越权操作",
        1: "有限信息泄露",
        0: "无实际安全影响",
    }
    return descs.get(i, "未知")

def get_complexity_desc(c: int) -> str:
    """获取利用复杂度描述"""
    descs = {
        3: "单次请求即可利用",
        2: "需要构造特殊 payload 或多步操作",
        1: "需要特定环境/竞态条件/链式利用",
        0: "有效防护，无法绕过",
    }
    return descs.get(c, "未知")

def apply_cvss_to_finding(finding: Dict, sequence: int = 1) -> Dict:
    """将 CVSS 评分应用到审计发现

    Args:
        finding: 审计发现
        sequence: 漏洞序号

    Returns:
        Dict: 更新后的审计发现
    """
    vuln_type = finding.get('type', 'UNKNOWN')
    legacy_severity = finding.get('severity', '中危')

    cvss_result = calculate_from_finding(
        vuln_type=vuln_type,
        override_severity=legacy_severity,
    )

    vuln_id = generate_vuln_id(vuln_type, cvss_result.severity, sequence)

    finding['cvss_score'] = cvss_result.score
    finding['cvss'] = cvss_result.cvss
    finding['severity'] = cvss_result.severity
    finding['vuln_id'] = vuln_id
    finding['reachability'] = cvss_result.reachability
    finding['impact'] = cvss_result.impact
    finding['complexity'] = cvss_result.complexity

    return finding

def batch_apply_cvss(findings: list) -> list:
    """批量应用 CVSS 评分

    Args:
        findings: 审计发现列表

    Returns:
        list: 更新后的审计发现列表
    """
    type_counts: Dict[str, int] = {}

    for finding in findings:
        vuln_type = finding.get('type', 'UNKNOWN')
        if vuln_type not in type_counts:
            type_counts[vuln_type] = 0
        type_counts[vuln_type] += 1

        apply_cvss_to_finding(finding, type_counts[vuln_type])

    return findings
