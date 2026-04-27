import json
from pathlib import Path

fixes_file = Path(__file__).parent / "fixes.json"
with open(fixes_file, 'r', encoding='utf-8') as f:
    fixes = json.load(f)

llm_dir = Path("e:/code/gbt-code-audit-skill/findings/llm_audit")

for num, fix in fixes.items():
    matching_files = list(llm_dir.glob(f"{num}_*.md"))
    if matching_files:
        file_path = matching_files[0]
        content = file_path.read_text(encoding='utf-8')
        if "修复方案:" not in content:
            lines = content.strip().split('\n')
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if line.startswith("问题描述:"):
                    new_lines.append(f"修复方案: {fix}")
            file_path.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
            print(f"Updated {file_path.name}")
        else:
            print(f"Skipped {file_path.name} (already has fix)")
    else:
        print(f"Not found {num}_*.md")

print("Done!")
