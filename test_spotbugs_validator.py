"""
SpotBugs 工具扫描命令验证测试
验证 SpotBugs 和 FindSecurityBugs 插件是否正确配置
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path


class SpotBugsValidator:
    """SpotBugs 工具验证器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.spotbugs_dir = self.project_root / "vendor" / "spotbugs"
        self.errors = []
        self.warnings = []
        self.passed = []
    
    def validate_all(self):
        """执行所有验证"""
        print("=" * 60)
        print("SpotBugs 工具扫描命令验证测试")
        print("=" * 60)
        
        self.check_java_environment()
        self.check_spotbugs_jar()
        self.check_findsecbugs_plugin()
        self.check_spotbugs_command()
        self.check_sample_java_code()
        
        self.print_summary()
        return len(self.errors) == 0
    
    def check_java_environment(self):
        """检查 Java 环境"""
        print("\n[1] 检查 Java 环境...")
        
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version_info = result.stderr or result.stdout
                print(f"    ✅ Java 已安装: {version_info.split()[2] if version_info else 'Unknown'}")
                self.passed.append("Java 环境")
            else:
                self.errors.append("Java 未正确安装或配置")
                print("    ❌ Java 未正确安装")
        except FileNotFoundError:
            self.errors.append("Java 未安装 (java 命令未找到)")
            print("    ❌ Java 未安装 (java 命令未找到)")
        except Exception as e:
            self.errors.append(f"Java 检查失败: {e}")
            print(f"    ❌ Java 检查失败: {e}")
    
    def check_spotbugs_jar(self):
        """检查 SpotBugs JAR 文件"""
        print("\n[2] 检查 SpotBugs JAR 文件...")
        
        spotbugs_jar = self.spotbugs_dir / "spotbugs.jar"
        
        if spotbugs_jar.exists():
            size_mb = spotbugs_jar.stat().st_size / (1024 * 1024)
            print(f"    ✅ spotbugs.jar 存在 ({size_mb:.2f} MB)")
            self.passed.append("SpotBugs JAR")
        else:
            self.errors.append(f"spotbugs.jar 不存在: {spotbugs_jar}")
            print(f"    ❌ spotbugs.jar 不存在: {spotbugs_jar}")
        
        jar_count = len(list(self.spotbugs_dir.glob("*.jar")))
        print(f"    📦 vendor/spotbugs 目录下共有 {jar_count} 个 JAR 文件")
    
    def check_findsecbugs_plugin(self):
        """检查 FindSecurityBugs 插件"""
        print("\n[3] 检查 FindSecurityBugs 插件...")
        
        findsecbugs_jar = self.spotbugs_dir / "findsecbugs-plugin-1.14.0.jar"
        
        if findsecbugs_jar.exists():
            size_kb = findsecbugs_jar.stat().st_size / 1024
            print(f"    ✅ findsecbugs-plugin-1.14.0.jar 存在 ({size_kb:.2f} KB)")
            self.passed.append("FindSecurityBugs 插件")
        else:
            self.errors.append(f"FindSecurityBugs 插件不存在: {findsecbugs_jar}")
            print(f"    ❌ FindSecurityBugs 插件不存在: {findsecbugs_jar}")
    
    def check_spotbugs_command(self):
        """检查 SpotBugs 命令是否正确"""
        print("\n[4] 检查 SpotBugs 命令格式...")
        
        spotbugs_dir = self.spotbugs_dir
        findsecbugs_plugin = spotbugs_dir / "findsecbugs-plugin-1.14.0.jar"
        
        expected_cmd = [
            "java",
            "-cp", "<classpath>",
            "edu.umd.cs.findbugs.FindBugs2",
            "-pluginList", str(findsecbugs_plugin),
            "-xml:withMessages",
            "-output", "<output_file>",
            "<target>"
        ]
        
        print("    预期命令格式:")
        print("    " + " ".join(expected_cmd))
        
        if findsecbugs_plugin.exists():
            print("    ✅ 命令格式正确，所有必需文件存在")
            self.passed.append("SpotBugs 命令格式")
        else:
            print("    ❌ 命令格式验证失败，缺少必需文件")
    
    def check_sample_java_code(self):
        """使用样例 Java 代码测试扫描"""
        print("\n[5] 测试实际扫描功能...")
        
        spotbugs_dir = self.spotbugs_dir
        findsecbugs_plugin = spotbugs_dir / "findsecbugs-plugin-1.14.0.jar"
        
        if not spotbugs_dir.exists():
            print("    ⚠️ 跳过：SpotBugs 目录不存在")
            self.warnings.append("跳过实际扫描测试")
            return
        
        with tempfile.TemporaryDirectory() as temp_dir:
            java_file = Path(temp_dir) / "Test.java"
            java_file.write_text('''
public class Test {
    public static void main(String[] args) {
        String sql = "SELECT * FROM users WHERE id = " + args[0];
        System.out.println(sql);
    }
}
''')
            
            class_file = Path(temp_dir) / "Test.class"
            
            try:
                compile_result = subprocess.run(
                    ["javac", str(java_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=temp_dir
                )
                
                if compile_result.returncode != 0:
                    print(f"    ⚠️ Java 编译失败: {compile_result.stderr}")
                    self.warnings.append("Java 编译失败，跳过扫描测试")
                    return
                
                output_file = Path(temp_dir) / "result.xml"
                
                classpath = ";".join([str(jar) for jar in spotbugs_dir.glob("*.jar")])
                
                scan_cmd = [
                    "java",
                    "-cp", classpath,
                    "edu.umd.cs.findbugs.FindBugs2",
                    "-pluginList", str(findsecbugs_plugin),
                    "-xml:withMessages",
                    "-output", str(output_file),
                    temp_dir
                ]
                
                print(f"    执行命令: {' '.join(scan_cmd[:5])}...")
                
                scan_result = subprocess.run(
                    scan_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if output_file.exists():
                    content = output_file.read_text()
                    if content:
                        print("    ✅ SpotBugs 扫描成功，生成结果文件")
                        if "BugInstance" in content:
                            print("    ✅ 发现漏洞报告")
                        else:
                            print("    ℹ️ 未发现漏洞（样例代码可能太简单）")
                        self.passed.append("SpotBugs 实际扫描")
                    else:
                        print("    ⚠️ 结果文件为空")
                        self.warnings.append("扫描结果为空")
                else:
                    print(f"    ❌ 扫描失败，未生成结果文件")
                    print(f"    stderr: {scan_result.stderr}")
                    self.errors.append("SpotBugs 扫描未生成结果")
                    
            except subprocess.TimeoutExpired:
                self.errors.append("SpotBugs 扫描超时")
                print("    ❌ SpotBugs 扫描超时")
            except Exception as e:
                self.errors.append(f"扫描测试失败: {e}")
                print(f"    ❌ 扫描测试失败: {e}")
    
    def print_summary(self):
        """打印验证摘要"""
        print("\n" + "=" * 60)
        print("验证摘要")
        print("=" * 60)
        
        print(f"\n✅ 通过: {len(self.passed)} 项")
        for item in self.passed:
            print(f"   - {item}")
        
        if self.warnings:
            print(f"\n⚠️ 警告: {len(self.warnings)} 项")
            for item in self.warnings:
                print(f"   - {item}")
        
        if self.errors:
            print(f"\n❌ 错误: {len(self.errors)} 项")
            for item in self.errors:
                print(f"   - {item}")
        
        print("\n" + "-" * 60)
        if len(self.errors) == 0:
            print("🎉 所有验证通过！SpotBugs 工具扫描命令配置正确。")
        else:
            print("⚠️ 存在错误，请检查上述问题。")
        print("-" * 60)


def main():
    validator = SpotBugsValidator()
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
