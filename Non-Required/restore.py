import json
import os

transcript_path = r'C:\Users\bhima\.gemini\antigravity-ide\brain\61cf01ea-7bee-41fd-8cb4-4fff8ba71fdc\.system_generated\logs\transcript_full.jsonl'
files = {}

with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            data = json.loads(line)
            if 'tool_calls' in data:
                for call in data['tool_calls']:
                    name = call['function']['name']
                    if name in ['default_api:write_to_file', 'default_api:replace_file_content', 'default_api:multi_replace_file_content']:
                        args = json.loads(call['function']['arguments'])
                        if 'TargetFile' in args:
                            fp = args['TargetFile']
                            if fp not in files:
                                files[fp] = []
                            files[fp].append(args)
        except Exception as e:
            pass

print("Files modified:")
for fp, versions in files.items():
    print(f"File: {fp} (versions: {len(versions)})")
    # For each file that has multiple versions, let's dump the one right before the last ones
    if len(versions) >= 2:
        # We need to figure out which one is the original.
        # Actually, let's just write all versions to a dump folder so we can inspect them.
        pass

# Specifically for the ones I modified in the last request:
targets = [
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\app\layout.tsx",
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\app\globals.css",
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\components\layout\Sidebar.tsx",
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\components\layout\Navbar.tsx",
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\app\(dashboard)\dashboard\page.tsx",
    r"c:\Users\bhima\Desktop\Injection Lab\frontend\src\components\dashboard\DashboardCharts.tsx"
]

import shutil
os.makedirs("C:/Users/bhima/Desktop/revert_dump", exist_ok=True)

for t in targets:
    if t in files and len(files[t]) >= 2:
        # The original is likely the first or the second to last.
        # Wait, if I modified it multiple times, the version before the last few is the one.
        # Let's just dump the previous state that I modified in the last turn.
        # The last turn was when the user asked for Dribbble. I can just take the version before the last one for files that only have 2 versions.
        # For globals.css, the first one is probably the original before Dribbble.
        # Let's dump all versions for these files.
        for idx, v in enumerate(files[t]):
            fname = os.path.basename(t)
            with open(f"C:/Users/bhima/Desktop/revert_dump/{fname}_v{idx}.json", 'w') as out:
                json.dump(v, out)
