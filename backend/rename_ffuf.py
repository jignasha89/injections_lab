import os

files = [
    r'c:\Users\bhima\Desktop\Injection Lab\backend\python_engine\backend\engine\crawler\fuzzer.py',
    r'c:\Users\bhima\Desktop\Injection Lab\backend\python_engine\backend\engine\tools\ffuf_adapter.py'
]

for filepath in files:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Change tool name in logs
    content = content.replace(', "ffuf",', ', "fuzzer",')
    
    # 2. Hide raw command
    content = content.replace("f\"Running: {' '.join(cmd)}\"", '"Initiating background fuzzing engine..."')
    
    # 3. Rename output messages
    content = content.replace('Ffuf', 'Fuzzer')
    content = content.replace('ffuf fuzzing', 'Background fuzzing')
    content = content.replace('ffuf:', 'Fuzzer:')
    content = content.replace('ffuf ', 'fuzzer ')
    
    # 4. Add silent flag to FFUF
    content = content.replace('"-noninteractive",', '"-noninteractive", "-s",')
    content = content.replace('cmd.extend(["-t",', 'cmd.extend(["-s", "-t",')
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

print("Replacement complete.")
