"""
gbt-code-audit-skill 单元测试
"""
try:
    import pytest
except ImportError:
    pytest = None

import json
from pathlib import Path
import sys

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from skill import (
    quick_scan_patterns,
    parse_finding_md,
    validate_code_snippet,
    deduplicate_findings,
    compute_stats,
    _get_severity_icon,
    _get_source_icon,
)


class TestQuickScanPatterns:
    """测试快速扫描模式"""

    def test_patterns_exist_for_all_languages(self):
        """所有语言都有扫描模式"""
        patterns = quick_scan_patterns()
        assert "java" in patterns
        assert "python" in patterns
        assert "cpp" in patterns
        assert "csharp" in patterns

    def test_java_patterns_count(self):
        """Java 模式数量"""
        patterns = quick_scan_patterns()
        assert len(patterns["java"]) >= 10

    def test_python_patterns_count(self):
        """Python 模式数量"""
        patterns = quick_scan_patterns()
        assert len(patterns["python"]) >= 10

    def test_pattern_format(self):
        """模式格式正确（正则、类型、CWE、严重性）"""
        patterns = quick_scan_patterns()
        for lang, pattern_list in patterns.items():
            for pattern in pattern_list:
                assert len(pattern) == 4  # (regex, type, cwe, severity)
                assert pattern[2].startswith("CWE-")  # CWE 格式


class TestParseFindingMd:
    """测试 Markdown 解析"""

    def test_parse_english_fields(self):
        """解析英文字段（注意：parse_finding_md 只识别中文字段名）"""
        content = """
编号: #001
严重等级: 严重
漏洞类型: 命令注入
文件路径: test-samples/java/VulnerableJava.java
行号: 31
CWE: CWE-78
国标映射: GB/T34944-6.2.3.3 命令注入
来源: quick_scan
语言: java
问题代码: Runtime.getRuntime().exec(command);
问题描述: 描述内容
修复方案: 修复内容
验证方法: 验证内容
"""
        result = parse_finding_md(content)
        assert result["id"] == "#001"
        assert result["severity"] == "严重"
        assert result["line"] == 31

    def test_parse_chinese_fields(self):
        """解析中文字段"""
        content = """
编号：#001
严重等级：严重
漏洞类型：命令注入
文件路径：test-samples/java/VulnerableJava.java
行号：31
CWE：CWE-78
国标映射：GB/T34944-6.2.3.3 命令注入
来源：quick_scan
语言：java
问题代码：Runtime.getRuntime().exec(command);
问题描述：描述内容
修复方案：修复内容
验证方法：验证内容
"""
        result = parse_finding_md(content)
        assert result["id"] == "#001"
        assert result["severity"] == "严重"
        assert result["line"] == 31

    def test_parse_multiline_code_snippet(self):
        """解析多行代码片段"""
        content = """
问题代码：
    line 1
    line 2
    line 3
"""
        result = parse_finding_md(content)
        assert "line 1" in result.get("code_snippet", "")


class TestValidateCodeSnippet:
    """测试代码片段验证"""

    def test_validate_empty_file(self):
        """空文件路径跳过验证"""
        finding = {"file": "", "line": 0, "code_snippet": ""}
        result = validate_code_snippet(finding)
        assert result["valid"] == True
        assert result["reason"] == "skip"

    def test_validate_file_not_found(self):
        """文件不存在"""
        finding = {"file": "nonexistent.py", "line": 1, "code_snippet": "test"}
        result = validate_code_snippet(finding)
        assert result["valid"] == True
        assert result["reason"] == "file_not_found"


class TestDeduplicateFindings:
    """测试去重功能"""

    def test_deduplicate_same_file_line_type(self):
        """相同文件、行号、类型去重"""
        findings = [
            {"file": "test.py", "line": 10, "type": "SQL_INJECTION", "source": "quick_scan"},
            {"file": "test.py", "line": 10, "type": "SQL_INJECTION", "source": "llm_audit"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["source"] == "llm_audit"  # 优先保留 LLM 审计

    def test_deduplicate_different_line(self):
        """不同行号不去重"""
        findings = [
            {"file": "test.py", "line": 10, "type": "SQL_INJECTION", "source": "quick_scan"},
            {"file": "test.py", "line": 20, "type": "SQL_INJECTION", "source": "llm_audit"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_deduplicate_different_type(self):
        """不同类型不去重"""
        findings = [
            {"file": "test.py", "line": 10, "type": "SQL_INJECTION", "source": "quick_scan"},
            {"file": "test.py", "line": 10, "type": "COMMAND_INJECTION", "source": "llm_audit"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2


class TestComputeStats:
    """测试统计功能"""

    def test_compute_severity_stats(self):
        """严重程度统计"""
        findings = [
            {"severity": "严重", "source": "quick_scan"},
            {"severity": "严重", "source": "llm_audit"},
            {"severity": "高危", "source": "quick_scan"},
        ]
        stats = compute_stats(findings)
        assert stats["severity_stats"]["严重"] == 2
        assert stats["severity_stats"]["高危"] == 1

    def test_compute_source_stats(self):
        """来源统计"""
        findings = [
            {"severity": "严重", "source": "quick_scan"},
            {"severity": "严重", "source": "llm_audit"},
            {"severity": "高危", "source": "quick_scan"},
        ]
        stats = compute_stats(findings)
        assert stats["source_stats"]["quick_scan"] == 2
        assert stats["source_stats"]["llm_audit"] == 1

    def test_compute_total_count(self):
        """总数统计"""
        findings = [{"severity": "严重"}, {"severity": "高危"}]
        stats = compute_stats(findings)
        assert stats["total_count"] == 2


class TestIcons:
    """测试图标函数"""

    def test_severity_icon_critical(self):
        """严重图标"""
        assert _get_severity_icon("严重") == "🔴"

    def test_severity_icon_high(self):
        """高危图标"""
        assert _get_severity_icon("高危") == "🟠"

    def test_severity_icon_medium(self):
        """中危图标"""
        assert _get_severity_icon("中危") == "🟡"

    def test_severity_icon_low(self):
        """低危图标"""
        assert _get_severity_icon("低危") == "🟢"

    def test_severity_icon_unknown(self):
        """未知图标"""
        assert _get_severity_icon("未知") == "⚪"

    def test_source_icon_quick_scan(self):
        """快速扫描图标"""
        assert "快速扫描" in _get_source_icon("quick_scan")

    def test_source_icon_llm_audit(self):
        """LLM 审计图标"""
        assert "LLM审计" in _get_source_icon("llm_audit")


def run_tests():
    """手动运行测试"""
    test_classes = [
        TestQuickScanPatterns,
        TestParseFindingMd,
        TestValidateCodeSnippet,
        TestDeduplicateFindings,
        TestComputeStats,
        TestIcons,
    ]

    passed = 0
    failed = 0

    for test_class in test_classes:
        instance = test_class()
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                try:
                    method = getattr(instance, method_name)
                    method()
                    print(f"✅ {test_class.__name__}.{method_name}")
                    passed += 1
                except AssertionError as e:
                    print(f"❌ {test_class.__name__}.{method_name}: {e}")
                    failed += 1
                except Exception as e:
                    print(f"❌ {test_class.__name__}.{method_name}: {e}")
                    failed += 1

    print(f"\n总计: {passed} 通过, {failed} 失败")
    return failed == 0


if __name__ == "__main__":
    if pytest:
        pytest.main([__file__, "-v"])
    else:
        run_tests()