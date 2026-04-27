"""
审计覆盖率检查工具 - 预防措施
确保LLM审计覆盖全部代码文件
"""
import json
import sys
from pathlib import Path
from datetime import datetime


class AuditCoverageChecker:
    """审计覆盖率检查器"""
    
    def __init__(self, target_dir, llm_audit_dir, baseline_dir):
        self.target_dir = Path(target_dir)
        self.llm_audit_dir = Path(llm_audit_dir)
        self.baseline_dir = Path(baseline_dir)
        self.source_files = []
        self.audited_files = []
        self.baseline_files = []
        
    def scan_source_files(self):
        """扫描所有源代码文件"""
        extensions = ['*.java', '*.py', '*.cpp', '*.c', '*.cs', '*.h', '*.hpp']
        for ext in extensions:
            self.source_files.extend(self.target_dir.rglob(ext))
        return len(self.source_files)
    
    def scan_llm_audit_files(self):
        """扫描LLM审计文件"""
        if self.llm_audit_dir.exists():
            self.audited_files = list(self.llm_audit_dir.glob('*.md'))
        return len(self.audited_files)
    
    def scan_baseline_files(self):
        """扫描基线文件"""
        if self.baseline_dir.exists():
            self.baseline_files = list(self.baseline_dir.glob('*.md'))
        return len(self.baseline_files)
    
    def extract_source_files_from_md(self, md_files):
        """从md文件中提取源文件路径"""
        source_files = set()
        for md_file in md_files:
            content = md_file.read_text(encoding='utf-8')
            for line in content.split('\n'):
                if line.startswith('文件路径:') or line.startswith('**文件**:'):
                    file_path = line.split(':', 1)[1].strip()
                    # 提取文件名
                    basename = Path(file_path).name
                    source_files.add(basename)
                    break
        return source_files
    
    def check_coverage(self):
        """检查审计覆盖率"""
        # 扫描文件
        total_source = self.scan_source_files()
        total_llm = self.scan_llm_audit_files()
        total_baseline = self.scan_baseline_files()
        
        # 提取已审计的源文件
        llm_source_files = self.extract_source_files_from_md(self.audited_files)
        baseline_source_files = self.extract_source_files_from_md(self.baseline_files)
        
        # 计算覆盖率
        source_basenames = {f.name for f in self.source_files}
        llm_coverage = len(llm_source_files & source_basenames) / len(source_basenames) * 100 if source_basenames else 0
        baseline_coverage = len(baseline_source_files & source_basenames) / len(source_basenames) * 100 if source_basenames else 0
        
        # 找出未审计的文件
        unaudited = source_basenames - llm_source_files
        
        return {
            'total_source_files': total_source,
            'total_llm_audit_files': total_llm,
            'total_baseline_files': total_baseline,
            'llm_coverage_rate': llm_coverage,
            'baseline_coverage_rate': baseline_coverage,
            'unaudited_files': sorted(list(unaudited)),
            'unaudited_count': len(unaudited)
        }
    
    def generate_report(self):
        """生成覆盖率检查报告"""
        result = self.check_coverage()
        
        report = f"""# 审计覆盖率检查报告

**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**目标目录**: {self.target_dir}

## 统计摘要

| 指标 | 数值 |
|------|------|
| 源代码文件总数 | {result['total_source_files']} |
| LLM审计文件数 | {result['total_llm_audit_files']} |
| 快速扫描基线数 | {result['total_baseline_files']} |
| **LLM审计覆盖率** | **{result['llm_coverage_rate']:.1f}%** |
| 快速扫描覆盖率 | {result['baseline_coverage_rate']:.1f}% |
| 未审计文件数 | {result['unaudited_count']} |

## 覆盖率状态

"""
        if result['llm_coverage_rate'] >= 100:
            report += "✅ **LLM审计覆盖率达标（100%）**\n\n"
        elif result['llm_coverage_rate'] >= 90:
            report += "⚠️ **LLM审计覆盖率接近达标，但仍有遗漏**\n\n"
        else:
            report += f"❌ **LLM审计覆盖率不达标（{result['llm_coverage_rate']:.1f}% < 100%）**\n\n"
        
        if result['unaudited_files']:
            report += f"## 未审计文件列表（{len(result['unaudited_files'])}个）\n\n"
            report += "| 序号 | 文件名 |\n|------|--------|\n"
            for i, filename in enumerate(result['unaudited_files'], 1):
                report += f"| {i} | {filename} |\n"
            report += "\n"
            
            report += "### 建议操作\n\n"
            report += "1. **立即补充审计**：对上述未审计文件进行LLM审计\n"
            report += "2. **重新计算检出率**：补充审计后重新运行检出率分析\n"
            report += "3. **验证审计完整性**：确保每个文件都被审计\n\n"
        else:
            report += "✅ **所有源代码文件均已审计**\n\n"
        
        report += """## 预防措施检查清单

### 审计前
- [ ] 使用Glob获取全部代码文件列表
- [ ] 记录文件总数
- [ ] 确认审计策略覆盖全部文件

### 审计中
- [ ] 每审计一个文件标记进度
- [ ] 定期检查覆盖率
- [ ] 发现未审计文件立即补充

### 审计后
- [ ] 运行覆盖率检查工具
- [ ] 确认覆盖率达到100%
- [ ] 如有遗漏，补充审计

## 自动化检查命令

```bash
# 运行覆盖率检查
python scripts/audit_coverage_checker.py --target <项目目录> --llm_audit <llm_audit目录> --baseline <baseline目录>

# 检查源代码文件数
Glob path="<项目目录>" pattern="**/*.java"

# 检查LLM审计文件数
Glob path="<llm_audit目录>" pattern="*.md"
```
"""
        return report


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='审计覆盖率检查工具')
    parser.add_argument('--target', required=True, help='目标项目目录')
    parser.add_argument('--llm_audit', required=True, help='LLM审计目录')
    parser.add_argument('--baseline', required=True, help='基线目录')
    parser.add_argument('--output', help='输出报告路径（可选）')
    
    args = parser.parse_args()
    
    checker = AuditCoverageChecker(args.target, args.llm_audit, args.baseline)
    report = checker.generate_report()
    
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(report, encoding='utf-8')
        print(f"覆盖率检查报告已生成: {output_path}")
    else:
        print(report)
    
    # 返回退出码
    result = checker.check_coverage()
    if result['llm_coverage_rate'] < 100:
        print(f"\n⚠️ 警告：LLM审计覆盖率仅为 {result['llm_coverage_rate']:.1f}%")
        print(f"   未审计文件数: {result['unaudited_count']}")
        return 1
    else:
        print(f"\n✅ LLM审计覆盖率达标: {result['llm_coverage_rate']:.1f}%")
        return 0


if __name__ == '__main__':
    sys.exit(main())
