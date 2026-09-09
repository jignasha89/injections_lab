"""
Mitigation Database - Comprehensive remediation data for 50+ injection sub-types.

Each entry includes:
- Plain English description
- Code-level remediation guidance
- Before/after code examples in Python, JavaScript, PHP, Java, C#, Go
- ModSecurity WAF rules
- Reference links
"""

from typing import Dict, List, Any

MITIGATION_DB: Dict[str, Dict[str, Any]] = {

    # ─── SQL INJECTION ──────────────────────────────────────────────────────

    "sql_injection_classic": {
        "title": "Classic SQL Injection",
        "description": (
            "Attacker injects arbitrary SQL statements into input fields that are "
            "concatenated directly into database queries. This can lead to full "
            "database compromise including data exfiltration, authentication bypass, "
            "and arbitrary command execution on the database server."
        ),
        "remediation": (
            "Use parameterized queries (prepared statements) for all database access. "
            "Never concatenate user input into SQL strings. Apply least-privilege "
            "database accounts and validate input against allowlists."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(\"SELECT * FROM users WHERE id='\" + user_input + \"'\")",
                "fixed": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_input,))",
            },
            "javascript": {
                "vulnerable": "db.query(`SELECT * FROM users WHERE id='${userInput}'`)",
                "fixed": "db.query('SELECT * FROM users WHERE id = ?', [userInput])",
            },
            "php": {
                "vulnerable": "$result = mysqli_query($conn, \"SELECT * FROM users WHERE id='\" . $_GET['id'] . \"'\");",
                "fixed": "$stmt = $conn->prepare('SELECT * FROM users WHERE id = ?'); $stmt->bind_param('s', $_GET['id']); $stmt->execute();",
            },
            "java": {
                "vulnerable": "Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id='\" + input + \"'\");",
                "fixed": "PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); ps.setString(1, input); ResultSet rs = ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "var cmd = new SqlCommand(\"SELECT * FROM users WHERE id='\" + input + \"'\", conn);",
                "fixed": "var cmd = new SqlCommand('SELECT * FROM users WHERE id = @id', conn); cmd.Parameters.AddWithValue('@id', input);",
            },
            "go": {
                "vulnerable": "rows, _ := db.Query(\"SELECT * FROM users WHERE id='\" + input + \"'\")",
                "fixed": "rows, _ := db.Query(\"SELECT * FROM users WHERE id = ?\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS|ARGS_NAMES|REQUEST_URI \"@rx (?i)(\\b(select|insert|update|delete|drop|union|exec|execute)\\b)\" \"id:1001,phase:2,deny,status:403,log,msg:'SQL Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },

    "sql_injection_union": {
        "title": "UNION-based SQL Injection",
        "description": (
            "Attacker uses UNION SELECT to append additional queries to the original "
            "query, extracting data from arbitrary tables."
        ),
        "remediation": (
            "Use parameterized queries. Restrict database account permissions. "
            "Implement WAF rules to detect UNION keywords. Validate and restrict "
            "input length and character sets."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(f\"SELECT name, price FROM products WHERE id={product_id}\")",
                "fixed": "cursor.execute(\"SELECT name, price FROM products WHERE id = %s\", (product_id,))",
            },
            "javascript": {
                "vulnerable": "db.query(`SELECT name, price FROM products WHERE id=${productId}`)",
                "fixed": "db.query('SELECT name, price FROM products WHERE id = ?', [productId])",
            },
            "php": {
                "vulnerable": "$result = mysqli_query($conn, \"SELECT name, price FROM products WHERE id=\" . $_GET['id']);",
                "fixed": "$stmt = $conn->prepare('SELECT name, price FROM products WHERE id = ?'); $stmt->bind_param('i', $_GET['id']); $stmt->execute();",
            },
            "java": {
                "vulnerable": "String q = \"SELECT name, price FROM products WHERE id=\" + input; stmt.executeQuery(q);",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT name, price FROM products WHERE id = ?\"); ps.setInt(1, Integer.parseInt(input)); ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "var cmd = new SqlCommand($\"SELECT name, price FROM products WHERE id={input}\", conn);",
                "fixed": "var cmd = new SqlCommand(\"SELECT name, price FROM products WHERE id = @id\", conn); cmd.Parameters.AddWithValue(\"@id\", input);",
            },
            "go": {
                "vulnerable": "rows, _ := db.Query(fmt.Sprintf(\"SELECT name, price FROM products WHERE id=%s\", input))",
                "fixed": "rows, _ := db.Query(\"SELECT name, price FROM products WHERE id = ?\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (?i)(union\\s+(all\\s+)?select)\" \"id:1002,phase:2,deny,status:403,log,msg:'UNION SQL Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://portswigger.net/web-security/sql-injection/union-attacks",
        ],
    },

    "sql_injection_blind_boolean": {
        "title": "Boolean-based Blind SQL Injection",
        "description": (
            "Attacker injects boolean conditions and observes application behavior "
            "(response content, timing) to infer database contents one bit at a time."
        ),
        "remediation": (
            "Use parameterized queries. Avoid boolean-based conditional logic that "
            "leaks information through observable differences in responses."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(f\"SELECT * FROM users WHERE id={uid} AND active=1\")",
                "fixed": "cursor.execute(\"SELECT * FROM users WHERE id = %s AND active=1\", (uid,))",
            },
            "javascript": {
                "vulnerable": "db.query(`SELECT * FROM users WHERE id=${uid} AND active=1`)",
                "fixed": "db.query('SELECT * FROM users WHERE id = ? AND active=1', [uid])",
            },
            "php": {
                "vulnerable": "$r = mysqli_query($conn, \"SELECT * FROM users WHERE id=\" . $_GET['id'] . \" AND active=1\");",
                "fixed": "$stmt = $conn->prepare('SELECT * FROM users WHERE id = ? AND active=1'); $stmt->bind_param('i', $_GET['id']); $stmt->execute();",
            },
            "java": {
                "vulnerable": "stmt.executeQuery(\"SELECT * FROM users WHERE id=\" + uid + \" AND active=1\");",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ? AND active=1\"); ps.setInt(1, uid); ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "new SqlCommand($\"SELECT * FROM users WHERE id={uid} AND active=1\", conn).ExecuteReader();",
                "fixed": "var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id AND active=1\", conn); cmd.Parameters.AddWithValue(\"@id\", uid); cmd.ExecuteReader();",
            },
            "go": {
                "vulnerable": "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id=%d AND active=1\", uid))",
                "fixed": "db.Query(\"SELECT * FROM users WHERE id = ? AND active=1\", uid)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (?i)(and|or)\\s+\\d+=\\d+\" \"id:1003,phase:2,deny,status:403,log,msg:'Blind SQL Injection Detected'\"",
            ],
        },
        "references": [
            "https://portswigger.net/web-security/sql-injection/blind",
        ],
    },

    "sql_injection_blind_time": {
        "title": "Time-based Blind SQL Injection",
        "description": (
            "Attacker uses database-specific delay functions (SLEEP, WAITFOR, pg_sleep) "
            "to infer data based on response timing."
        ),
        "remediation": (
            "Use parameterized queries. Implement consistent response times regardless "
            "of query results. Set query timeouts."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(f\"SELECT * FROM users WHERE id={uid}; WAITFOR DELAY '0:0:5'\")",
                "fixed": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
            },
            "javascript": {
                "vulnerable": "db.query(`SELECT * FROM users WHERE id=${uid}; WAITFOR DELAY '0:0:5'`)",
                "fixed": "db.query('SELECT * FROM users WHERE id = ?', [uid])",
            },
            "php": {
                "vulnerable": "mysqli_query($conn, \"SELECT * FROM users WHERE id=\" . $_GET['id'] . \"; WAITFOR DELAY '0:0:5'\");",
                "fixed": "$stmt = $conn->prepare('SELECT * FROM users WHERE id = ?'); $stmt->bind_param('i', $_GET['id']); $stmt->execute();",
            },
            "java": {
                "vulnerable": "stmt.executeQuery(\"SELECT * FROM users WHERE id=\" + uid + \"; WAITFOR DELAY '0:0:5'\");",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, uid); ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "new SqlCommand($\"SELECT * FROM users WHERE id={uid}; WAITFOR DELAY '0:0:5'\", conn).ExecuteReader();",
                "fixed": "var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn); cmd.Parameters.AddWithValue(\"@id\", uid); cmd.ExecuteReader();",
            },
            "go": {
                "vulnerable": "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id=%d; WAITFOR DELAY '0:0:5'\", uid))",
                "fixed": "db.Query(\"SELECT * FROM users WHERE id = ?\", uid)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (?i)(waitfor\\s+delay|sleep\\s*\\(|pg_sleep)\" \"id:1004,phase:2,deny,status:403,log,msg:'Time-based Blind SQL Injection Detected'\"",
            ],
        },
        "references": [
            "https://portswigger.net/web-security/sql-injection/blind#time-based",
        ],
    },

    "sql_injection_stacked": {
        "title": "Stacked Queries SQL Injection",
        "description": (
            "Attacker appends entirely new SQL statements separated by semicolons, "
            "enabling INSERT, UPDATE, DELETE, DROP, or EXEC commands."
        ),
        "remediation": (
            "Use parameterized queries. Disable stacked queries at the driver/ORM level. "
            "Apply least-privilege database permissions."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(f\"SELECT * FROM users WHERE id={uid}; DROP TABLE users\")",
                "fixed": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
            },
            "javascript": {
                "vulnerable": "db.query(`SELECT * FROM users WHERE id=${uid}; DROP TABLE users`)",
                "fixed": "db.query('SELECT * FROM users WHERE id = ?', [uid])",
            },
            "php": {
                "vulnerable": "mysqli_query($conn, \"SELECT * FROM users WHERE id=\" . $_GET['id'] . \"; DROP TABLE users\");",
                "fixed": "$stmt = $conn->prepare('SELECT * FROM users WHERE id = ?'); $stmt->bind_param('i', $_GET['id']); $stmt->execute();",
            },
            "java": {
                "vulnerable": "stmt.executeQuery(\"SELECT * FROM users WHERE id=\" + uid + \"; DROP TABLE users\");",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, uid); ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "new SqlCommand($\"SELECT * FROM users WHERE id={uid}; DROP TABLE users\", conn).ExecuteReader();",
                "fixed": "var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn); cmd.Parameters.AddWithValue(\"@id\", uid); cmd.ExecuteReader();",
            },
            "go": {
                "vulnerable": "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id=%d; DROP TABLE users\", uid))",
                "fixed": "db.Query(\"SELECT * FROM users WHERE id = ?\", uid)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx ;\\s*(drop|alter|create|truncate|insert|update|delete|exec)\\b\" \"id:1005,phase:2,deny,status:403,log,msg:'Stacked Query SQL Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },

    # ─── NOSQL INJECTION ────────────────────────────────────────────────────

    "nosql_injection_mongodb_operator": {
        "title": "MongoDB Operator Injection",
        "description": (
            "Attacker injects MongoDB operators ($gt, $ne, $regex) into JSON "
            "input fields to bypass authentication or extract data."
        ),
        "remediation": (
            "Validate input types strictly. Reject objects/arrays where primitives "
            "are expected. Use ORM/ODM schema validation. Never pass raw user "
            "input to MongoDB query operators."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "db.users.find({'username': request.json['username'], 'password': request.json['password']})",
                "fixed": "db.users.find({'username': str(request.json['username']), 'password': str(request.json['password'])})",
            },
            "javascript": {
                "vulnerable": "db.users.find({username: req.body.username, password: req.body.password})",
                "fixed": "db.users.find({username: String(req.body.username), password: String(req.body.password)})",
            },
            "php": {
                "vulnerable": "$collection->find(['username' => $_POST['username'], 'password' => $_POST['password']]);",
                "fixed": "$collection->find(['username' => (string)$_POST['username'], 'password' => (string)$_POST['password']]);",
            },
            "java": {
                "vulnerable": "Document filter = Document.parse(jsonString); collection.find(filter);",
                "fixed": "Document filter = new Document(\"username\", (String)map.get(\"username\")).append(\"password\", (String)map.get(\"password\")); collection.find(filter);",
            },
            "csharp": {
                "vulnerable": "var filter = Builders<BsonDocument>.Filter.Eq(\"username\", input);",
                "fixed": "var filter = Builders<BsonDocument>.Filter.Eq(\"username\", input.ToString());",
            },
            "go": {
                "vulnerable": "collection.FindOne(ctx, bson.M{\"username\": input})",
                "fixed": "collection.FindOne(ctx, bson.M{\"username\": fmt.Sprintf(\"%v\", input)})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx \\$(gt|ne|regex|where|gt\\e)\" \"id:1010,phase:2,deny,status:403,log,msg:'NoSQL Operator Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/943.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_NoSQL_Injection",
        ],
    },

    "nosql_injection_mongodb_javascript": {
        "title": "MongoDB JavaScript Injection",
        "description": (
            "Attacker injects JavaScript code into MongoDB queries using $where "
            "or MapReduce, leading to arbitrary code execution on the database server."
        ),
        "remediation": (
            "Disable $where queries. Use operator-based queries instead of JavaScript. "
            "If JavaScript is required, sandbox the execution environment."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "db.users.find({'$where': f'function(){{ return this.username == \"{user_input}\" }}'})",
                "fixed": "db.users.find({'username': user_input})",
            },
            "javascript": {
                "vulnerable": "db.users.find({$where: `function(){ return this.username == '${userInput}' }`})",
                "fixed": "db.users.find({username: userInput})",
            },
            "php": {
                "vulnerable": "$collection->find(['$where' => \"function(){ return this.username == '$_GET[user]' }\"]);",
                "fixed": "$collection->find(['username' => $_GET['user']]);",
            },
            "java": {
                "vulnerable": "collection.find(Filters.where(\"this.username == '\" + input + \"'\"));",
                "fixed": "collection.find(Filters.eq(\"username\", input));",
            },
            "csharp": {
                "vulnerable": "collection.Find(BsonDocument.Parse($\"{{\\$where: \\\"function(){{ return this.username == '{input}' }}\\\"}}\"));",
                "fixed": "collection.Find(Builders<BsonDocument>.Filter.Eq(\"username\", input));",
            },
            "go": {
                "vulnerable": "collection.Find(ctx, bson.M{\"$where\": fmt.Sprintf(\"function(){return this.username=='%s'}\", input)})",
                "fixed": "collection.Find(ctx, bson.M{\"username\": input})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx \\$where\" \"id:1011,phase:2,deny,status:403,log,msg:'NoSQL JavaScript Injection Detected'\"",
            ],
        },
        "references": [
            "https://docs.mongodb.com/manual/reference/operator/query/where/",
        ],
    },

    "nosql_injection_couchdb": {
        "title": "CouchDB Injection",
        "description": (
            "CouchDB views and Mango queries accept JSON-based input that can be "
            "manipulated to extract unauthorized data or execute design functions."
        ),
        "remediation": (
            "Validate and sanitize all query inputs. Use parameterized views. "
            "Restrict design document permissions."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "db.find({'selector': json.loads(request.data)})",
                "fixed": "db.find({'selector': {'username': str(request.json['username'])}})",
            },
            "javascript": {
                "vulnerable": "nano.db.find({selector: JSON.parse(req.body)})",
                "fixed": "nano.db.find({selector: {username: String(req.body.username)}})",
            },
            "php": {
                "vulnerable": "$couch->find(['selector' => json_decode(file_get_contents('php://input'), true)]);",
                "fixed": "$couch->find(['selector' => ['username' => (string)$_POST['username']]]);",
            },
            "java": {
                "vulnerable": "db.find(someInputJson);",
                "fixed": "db.find(new JsonDocument().put(\"username\", (String)map.get(\"username\")));",
            },
            "csharp": {
                "vulnerable": "var result = await db.FindAsync(rawJsonInput);",
                "fixed": "var result = await db.FindAsync(new { username = input.ToString() });",
            },
            "go": {
                "vulnerable": "db.Find(ctx, rawInput)",
                "fixed": "db.Find(ctx, map[string]interface{}{\"username\": fmt.Sprintf(\"%v\", input)})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx \\$regex|\\$nor|\\$exists|\\$gt\" \"id:1012,phase:2,deny,status:403,log,msg:'CouchDB Injection Detected'\"",
            ],
        },
        "references": [
            "https://couchdb.docs.htaccess.org/en/latest/api/database/find.html",
        ],
    },

    "nosql_injection_redis": {
        "title": "Redis Injection",
        "description": (
            "Attacker injects Redis commands via CRLF sequences in input, "
            "enabling unauthorized data access or modification."
        ),
        "remediation": (
            "Use parameterized Redis commands. Sanitize input for CRLF sequences. "
            "Enable Redis AUTH and ACL restrictions."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "r.get(f\"user:{user_input}\")",
                "fixed": "r.get(f\"user:{user_input}\")  # Use redis-py which auto-sanitizes",
            },
            "javascript": {
                "vulnerable": "redis.get(`user:${userInput}`)",
                "fixed": "redis.get('user', userInput)  // Use ioredis parameterized",
            },
            "php": {
                "vulnerable": "$redis->get('user:' . $_GET['id']);",
                "fixed": "$redis->get('user:' . preg_replace('/[\\r\\n]/', '', $_GET['id']));",
            },
            "java": {
                "vulnerable": "jedis.get(\"user:\" + input);",
                "fixed": "jedis.get(\"user:\" + input.replaceAll(\"[\\r\\n]\", \"\"));",
            },
            "csharp": {
                "vulnerable": "redis.StringGet(\"user:\" + input);",
                "fixed": "redis.StringGet(\"user:\" + Regex.Replace(input, @\"[\\r\\n]\", \"\"));",
            },
            "go": {
                "vulnerable": "rdb.Get(ctx, \"user:\"+input).Result()",
                "fixed": "rdb.Get(ctx, \"user:\"+strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(input)).Result()",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\r|\\n).*(flushall|flushdb|keys|config|debug|eval)\" \"id:1013,phase:2,deny,status:403,log,msg:'Redis Injection Detected'\"",
            ],
        },
        "references": [
            "https://book.hacktricks.xyz/network-services-pentesting/6379-redis",
        ],
    },

    # ─── OS COMMAND INJECTION ───────────────────────────────────────────────

    "os_command_injection_shell_metacharacters": {
        "title": "Shell Metacharacter Command Injection",
        "description": (
            "Attacker injects shell metacharacters (;, |, &&, ||, `, $()) "
            "to chain or redirect OS commands."
        ),
        "remediation": (
            "Never pass user input to shell commands. Use language-native APIs "
            "for file operations, process execution, etc. If shell is required, "
            "use subprocess with argument lists (Python), execFile (Node.js)."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "os.system(f'ping {user_input}')",
                "fixed": "subprocess.run(['ping', '-c', '1', user_input], capture_output=True)",
            },
            "javascript": {
                "vulnerable": "execSync(`ping -c 1 ${userInput}`)",
                "fixed": "execFileSync('ping', ['-c', '1', userInput])",
            },
            "php": {
                "vulnerable": "exec('ping -c 1 ' . $_GET['host']);",
                "fixed": "exec('ping -c 1 ' . escapeshellarg($_GET['host']));",
            },
            "java": {
                "vulnerable": "Runtime.getRuntime().exec(\"ping -c 1 \" + input);",
                "fixed": "new ProcessBuilder(\"ping\", \"-c\", \"1\", input).start();",
            },
            "csharp": {
                "vulnerable": "Process.Start(\"ping\", $\"-c 1 {input}\");",
                "fixed": "Process.Start(new ProcessStartInfo(\"ping\", \"-c 1\") { ArgumentList = { input } });",
            },
            "go": {
                "vulnerable": "exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+input)",
                "fixed": "exec.Command(\"ping\", \"-c\", \"1\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx [;|&\\$`\\(\\)]\" \"id:1020,phase:2,deny,status:403,log,msg:'Shell Metacharacter Command Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
    },

    "os_command_injection_chained": {
        "title": "Chained Command Injection",
        "description": (
            "Attacker uses chaining operators (&&, ||, ;) to execute multiple "
            "commands sequentially or conditionally."
        ),
        "remediation": (
            "Use language-native APIs. Validate input against strict allowlist "
            "of expected values. Use allowlist-based validation, not blocklist."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "os.system(f'dir {user_input}')",
                "fixed": "subprocess.run(['dir', user_input], shell=False, capture_output=True)",
            },
            "javascript": {
                "vulnerable": "execSync(`dir ${userInput}`)",
                "fixed": "execFileSync('dir', [userInput])",
            },
            "php": {
                "vulnerable": "shell_exec('dir ' . $_GET['path']);",
                "fixed": "exec('dir ' . escapeshellarg($_GET['path']));",
            },
            "java": {
                "vulnerable": "Runtime.getRuntime().exec(new String[]{'sh','-c','dir ' + input});",
                "fixed": "new ProcessBuilder(\"dir\", input).start();",
            },
            "csharp": {
                "vulnerable": "Process.Start(\"cmd.exe\", $\"/c dir {input}\");",
                "fixed": "Process.Start(new ProcessStartInfo(\"dir\") { ArgumentList = { input } });",
            },
            "go": {
                "vulnerable": "exec.Command(\"sh\", \"-c\", \"dir \"+input)",
                "fixed": "exec.Command(\"dir\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (&&|\\|\\||;)\" \"id:1021,phase:2,deny,status:403,log,msg:'Chained Command Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },

    "os_command_injection_windows": {
        "title": "Windows Command Injection",
        "description": (
            "Attacker exploits Windows-specific command injection vectors "
            "including cmd.exe /c, PowerShell, and batch file syntax."
        ),
        "remediation": (
            "Use .NET Process class with ArgumentList. Avoid cmd.exe /c. "
            "Validate inputs against strict allowlists."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "os.system(f'cmd /c dir {user_input}')",
                "fixed": "subprocess.run(['cmd', '/c', 'dir', user_input], capture_output=True)",
            },
            "javascript": {
                "vulnerable": "execSync(`cmd /c dir ${userInput}`)",
                "fixed": "execFileSync('cmd', ['/c', 'dir', userInput])",
            },
            "php": {
                "vulnerable": "exec('cmd /c dir ' . $_GET['path']);",
                "fixed": "exec('cmd /c dir ' . escapeshellarg($_GET['path']));",
            },
            "java": {
                "vulnerable": "Runtime.getRuntime().exec(new String[]{'cmd','/c','dir ' + input});",
                "fixed": "new ProcessBuilder(\"cmd\", \"/c\", \"dir\", input).start();",
            },
            "csharp": {
                "vulnerable": "Process.Start(\"cmd.exe\", $\"/c dir {input}\");",
                "fixed": "Process.Start(new ProcessStartInfo(\"cmd.exe\", $\"/c dir {input}\") { UseShellExecute = false, CreateNoWindow = true });",
            },
            "go": {
                "vulnerable": "exec.Command(\"cmd\", \"/c\", \"dir \"+input)",
                "fixed": "exec.Command(\"cmd\", \"/c\", \"dir\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (cmd\\.exe|powershell|pwsh)\" \"id:1022,phase:2,deny,status:403,log,msg:'Windows Command Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },

    # ─── LDAP INJECTION ─────────────────────────────────────────────────────

    "ldap_injection_search": {
        "title": "LDAP Search Filter Injection",
        "description": (
            "Attacker injects LDAP filter metacharacters (*, ), (, |, &) "
            "into search filters to modify query logic and extract or "
            "bypass authentication."
        ),
        "remediation": (
            "Escape all special LDAP characters using a library-specific "
            "escaping function. Use parameterized LDAP queries. Validate "
            "input against character allowlists."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "conn.search_s('ou=users', ldap.SCOPE_SUBTREE, f'(cn={user_input})')",
                "fixed": "from ldap3.utils.conv import escape_filter_tokens; conn.search_s('ou=users', ldap.SCOPE_SUBTREE, f'(cn={escape_filter_tokens(user_input)})')",
            },
            "javascript": {
                "vulnerable": "ldapClient.search(base, {filter: `(cn=${userInput})`})",
                "fixed": "const escaped = userInput.replace(/[*()\\\\]/g, '\\\\$&'); ldapClient.search(base, {filter: `(cn=${escaped})`});",
            },
            "php": {
                "vulnerable": "$ds->search('ou=users', '(cn=' . $_GET['name'] . ')');",
                "fixed": "$escaped = ldap_escape($_GET['name'], null, LDAP_ESCAPE_FILTER); $ds->search('ou=users', '(cn=' . $escaped . ')');",
            },
            "java": {
                "vulnerable": "DirContext ctx = new InitialDirContext(env); ctx.search(base, \"(cn=\" + input + \")\");",
                "fixed": "String escaped = javax.naming.ldap.Rfc2253Encoder.getInstance().encode(input); ctx.search(base, \"(cn=\" + escaped + \")\");",
            },
            "csharp": {
                "vulnerable": "DirectorySearcher.FindOne($\"(&(objectClass=user)(cn={input}))\");",
                "fixed": "DirectorySearcher.FindOne($\"(&(objectClass=user)(cn={EscapeLdapFilter(input)}))\");",
            },
            "go": {
                "vulnerable": "conn.Search(&ldap.SearchRequest{Filter: fmt.Sprintf(\"(cn=%s)\", input)})",
                "fixed": "conn.Search(&ldap.SearchRequest{Filter: ldap.EscapeFilter(input)})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx \\(|\\)|\\*|\\\\[0-9a-fA-F]{2}\" \"id:1030,phase:2,deny,status:403,log,msg:'LDAP Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/90.html",
            "https://owasp.org/www-community/attacks/LDAP_Injection",
        ],
    },

    "ldap_injection_auth_bypass": {
        "title": "LDAP Authentication Bypass",
        "description": (
            "Attacker injects always-true LDAP filter conditions "
            "(e.g., *)(uid=*))(| to bypass authentication."
        ),
        "remediation": (
            "Escape input properly. Use bind operations for authentication "
            "rather than search-based checks. Validate all filter values."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "conn.search_s(base, ldap.SCOPE_SUBTREE, f'(&(uid={user})(password={pwd}))')",
                "fixed": "conn.simple_bind_s(f'uid={escape_filter_tokens(user)},ou=users', pwd)",
            },
            "javascript": {
                "vulnerable": "ldapClient.search(base, {filter: `(&(uid=${user})(password=${pwd}))`})",
                "fixed": "ldapClient.bind(`uid=${user},ou=users`, pwd)",
            },
            "php": {
                "vulnerable": "$ds->search('ou=users', '(&(uid=' . $_POST['user'] . ')(password=' . $_POST['pass'] . '))');",
                "fixed": "$ds->bind('uid=' . $_POST['user'] . ',ou=users', $_POST['pass']);",
            },
            "java": {
                "vulnerable": "ctx.search(base, \"(&(uid=\" + user + \")(password=\" + pwd + \"))\");",
                "fixed": "ctx.bind(\"uid=\" + user + \",ou=users\", pwd);",
            },
            "csharp": {
                "vulnerable": "entry.Authenticate($\"(&(uid={user})(password={pwd}))\");",
                "fixed": "entry.Authenticate($\"uid={user},ou=users\", pwd);",
            },
            "go": {
                "vulnerable": "conn.Search(&ldap.SearchRequest{Filter: fmt.Sprintf(\"(&(uid=%s)(password=%s))\", user, pwd)})",
                "fixed": "conn.Bind(fmt.Sprintf(\"uid=%s,ou=users\", user), pwd)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx \\(\\|\\(|\\)\\)|\\(&\\(\" \"id:1031,phase:2,deny,status:403,log,msg:'LDAP Auth Bypass Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
    },

    # ─── XPATH INJECTION ────────────────────────────────────────────────────

    "xpath_injection_authentication": {
        "title": "XPath Authentication Bypass",
        "description": (
            "Attacker injects XPath expressions to bypass login forms "
            "by making authentication queries always return true."
        ),
        "remediation": (
            "Use parameterized XPath queries (XQuery with bound variables). "
            "Validate input against strict allowlists. Never construct XPath "
            "from raw user input."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "tree.xpath(f\"//user[username='{user}' and password='{pwd}']\")",
                "fixed": "tree.xpath('//user[username=$u and password=$p]', u=user, p=pwd)",
            },
            "javascript": {
                "vulnerable": "xpath.select(`//user[username='${user}' and password='${pwd}']`)",
                "fixed": "xpath.select1('//user[username=$u and password=$p]', {u: user, p: pwd})",
            },
            "php": {
                "vulnerable": "$xp->query(\"//user[username='\" . $_POST['user'] . \"' and password='\" . $_POST['pass'] . \"']\");",
                "fixed": "$xp->registerPHPFunctions('sanitize'); $xp->query('//user[username=php:function(\"sanitize\", $1) and password=php:function(\"sanitize\", $2)]', $user, $pwd);",
            },
            "java": {
                "vulnerable": "XPathExpression expr = xp.compile(\"//user[username='\" + user + \"' and password='\" + pwd + \"']\");",
                "fixed": "XPathVariableResolver resolver = new SimpleVariableResolver(Map.of(\"$u\", user, \"$p\", pwd)); expr = xp.compile(\"//user[username=$u and password=$p]\");",
            },
            "csharp": {
                "vulnerable": "doc.SelectNodes($\"//user[username='{user}' and password='{pwd}']\");",
                "fixed": "var nav = doc.CreateNavigator(); var ctx = new XPathNamespaceContext(); nav.Select($\"//user[username={EscapeXPath(user)} and password={EscapeXPath(pwd)}]\");",
            },
            "go": {
                "vulnerable": "xmlquery.QueryAll(doc, fmt.Sprintf(\"//user[username='%s' and password='%s']\", user, pwd))",
                "fixed": "xmlquery.QueryAll(doc, \"//user[username='' and password='']\") // Use a safe builder",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\bor\\b|\\band\\b|\\btrue\\b|\\bfalse\\b|\\bconcat\\b)\" \"id:1040,phase:2,deny,status:403,log,msg:'XPath Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/91.html",
            "https://owasp.org/www-community/vulnerabilities/XPath_Injection",
        ],
    },

    "xpath_injection_data_extraction": {
        "title": "XPath Data Extraction",
        "description": (
            "Attacker uses XPath string functions (concat, normalize-space, substring) "
            "and boolean tricks to enumerate XML document contents character by character."
        ),
        "remediation": (
            "Use parameterized XPath queries with variable bindings. "
            "Apply input validation to reject XPath metacharacters."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "tree.xpath(f\"//user[id='{uid}' or contains(name,'{partial}')]//text()\")",
                "fixed": "tree.xpath('//user[id=$id]//text()', id=uid)",
            },
            "javascript": {
                "vulnerable": "xpath.select(`//user[id='${uid}' or contains(name,'${partial}')]//text()`)",
                "fixed": "xpath.select1('//user[id=$id]//text()', {id: uid})",
            },
            "php": {
                "vulnerable": "$xp->query(\"//user[id='\" . $_GET['id'] . \"' or contains(name,'\" . $_GET['q'] . \"')]//text()\");",
                "fixed": "safeId = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['id']); $xp->query(\"//user[id='\" . $safeId . \"']//text()\");",
            },
            "java": {
                "vulnerable": "expr.evaluate(doc, XPathConstants.NODESET);",
                "fixed": "XPathExpression expr = xp.compile(\"//user[id=$id]//text()\"); expr.evaluate(doc, new SimpleVariableResolver(Map.of(\"$id\", uid)));",
            },
            "csharp": {
                "vulnerable": "doc.SelectNodes($\"//user[id='{uid}' or contains(name,'{q}')]//text()\");",
                "fixed": "doc.SelectNodes($\"//user[id='{SanitizeXPath(uid)}']//text()\");",
            },
            "go": {
                "vulnerable": "xmlquery.QueryAll(doc, fmt.Sprintf(\"//user[id='%s']//text()\", uid))",
                "fixed": "xmlquery.QueryAll(doc, \"//user[id='' and string-length(id)=0]//text()\")",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (concat|normalize-space|substring|contains|starts-with)\\s*\\(\" \"id:1041,phase:2,deny,status:403,log,msg:'XPath Data Extraction Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/91.html",
        ],
    },

    # ─── XXE ────────────────────────────────────────────────────────────────

    "xxe_file_read": {
        "title": "XXE File Read",
        "description": (
            "Attacker injects external entity references in XML input to read "
            "arbitrary files from the server (e.g., /etc/passwd, /etc/shadow)."
        ),
        "remediation": (
            "Disable external entity processing in XML parsers. "
            "Use defusedxml library. Set DTD processing to NONE."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "import xml.etree.ElementTree as ET; ET.fromstring(request.data)",
                "fixed": "import defusedxml.ElementTree as ET; ET.fromstring(request.data)",
            },
            "javascript": {
                "vulnerable": "const parser = new xml2js.Parser(); parser.parseString(xmlData);",
                "fixed": "const parser = new xml2js.Parser({explicitEntities: false}); // or use libxmljs with noent=false",
            },
            "php": {
                "vulnerable": "$doc = simplexml_load_string($xml);",
                "fixed": "$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET); libxml_disable_entity_loader(true);",
            },
            "java": {
                "vulnerable": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.newDocumentBuilder().parse(is);",
                "fixed": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
            },
            "csharp": {
                "vulnerable": "XmlDocument doc = new XmlDocument(); doc.LoadXml(xml);",
                "fixed": "XmlDocument doc = new XmlDocument(); doc.XmlResolver = null; doc.LoadXml(xml);",
            },
            "go": {
                "vulnerable": "xml.NewDecoder(r.Body).Decode(&result)",
                "fixed": "decoder := xml.NewDecoder(r.Body); decoder.Strict = true; // Use encoding/xml with restricted DTD",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx (SYSTEM|PUBLIC|\\[\\[\\[)\" \"id:1050,phase:2,deny,status:403,log,msg:'XXE File Read Attempt Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        ],
    },

    "xxe_ssrf": {
        "title": "XXE-based SSRF",
        "description": (
            "Attacker uses XXE to make the server issue requests to internal "
            "network services (SSRF via external entity URI resolution)."
        ),
        "remediation": (
            "Disable external entities and DTD processing entirely. "
            "Use defusedxml. Block outbound network requests from XML parsers."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "import xml.etree.ElementTree as ET; ET.fromstring(user_xml)",
                "fixed": "import defusedxml.ElementTree as ET; ET.fromstring(user_xml)",
            },
            "javascript": {
                "vulnerable": "xml2js.parseString(xmlData);",
                "fixed": "xml2js.parseString(xmlData, {explicitEntities: false, xmlns: false});",
            },
            "php": {
                "vulnerable": "simplexml_load_string($xml);",
                "fixed": "libxml_disable_entity_loader(true); simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);",
            },
            "java": {
                "vulnerable": "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);",
                "fixed": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
            },
            "csharp": {
                "vulnerable": "XDocument.Parse(xml);",
                "fixed": "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }; XmlReader.Create(new StringReader(xml), settings);",
            },
            "go": {
                "vulnerable": "xml.NewDecoder(body).Decode(&v)",
                "fixed": "// Use a custom resolver that blocks non-http/https schemes",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx (SYSTEM|PUBLIC)\\s+['\\\"]?(https?|ftp|file)://\" \"id:1051,phase:2,deny,status:403,log,msg:'XXE SSRF Attempt Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://portswigger.net/web-security/xxe",
        ],
    },

    "xxe_blind": {
        "title": "Blind XXE (Out-of-Band)",
        "description": (
            "Attacker uses OOB techniques (external DTD hosted on attacker server) "
            "to exfiltrate data when direct entity replacement is not reflected."
        ),
        "remediation": (
            "Disable DTD processing. Block outbound network connections from "
            "XML parsers. Use content-type validation."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "ET.fromstring(xml_data)",
                "fixed": "defusedxml.ElementTree.fromstring(xml_data)",
            },
            "javascript": {
                "vulnerable": "xml2js.parseString(xml);",
                "fixed": "xml2js.parseString(xml, {explicitEntities: false});",
            },
            "php": {
                "vulnerable": "simplexml_load_string($xml);",
                "fixed": "libxml_disable_entity_loader(true); simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOENT);",
            },
            "java": {
                "vulnerable": "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);",
                "fixed": "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
            },
            "csharp": {
                "vulnerable": "XmlDocument.Load(stream);",
                "fixed": "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };",
            },
            "go": {
                "vulnerable": "xml.NewDecoder(body).Decode(&v)",
                "fixed": "// Use a restricted decoder that blocks external DTDs",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx SYSTEM\\s+['\\\"]https?://\" \"id:1052,phase:2,deny,status:403,log,msg:'Blind XXE OOB Attempt Detected'\"",
            ],
        },
        "references": [
            "https://portswigger.net/web-security/xxe/blind",
        ],
    },

    "xxe_xinclude": {
        "title": "XXE via XInclude",
        "description": (
            "Attacker uses XInclude elements within XML to inject external "
            "entity references without full control over the XML document."
        ),
        "remediation": (
            "Disable XInclude processing in XML parsers. "
            "Validate XML structure before processing."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "ET.fromstring(xml_input)",
                "fixed": "defusedxml.ElementTree.fromstring(xml_input)",
            },
            "javascript": {
                "vulnerable": "xml2js.parseString(xml);",
                "fixed": "xml2js.parseString(xml, {explicitEntities: false});",
            },
            "php": {
                "vulnerable": "simplexml_load_string($xml);",
                "fixed": "simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOENT);",
            },
            "java": {
                "vulnerable": "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);",
                "fixed": "dbf.setXIncludeAware(false); dbf.setExpandEntityReferences(false);",
            },
            "csharp": {
                "vulnerable": "XDocument.Parse(xml);",
                "fixed": "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };",
            },
            "go": {
                "vulnerable": "xml.NewDecoder(body).Decode(&v)",
                "fixed": "// Use a decoder with XInclude disabled",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx <xi:include|<xinclude\" \"id:1053,phase:2,deny,status:403,log,msg:'XXE XInclude Attempt Detected'\"",
            ],
        },
        "references": [
            "https://portswigger.net/web-security/xxe",
        ],
    },

    # ─── HTML INJECTION ─────────────────────────────────────────────────────

    "html_injection_reflected": {
        "title": "Reflected HTML Injection",
        "description": (
            "Attacker injects HTML tags into input that are reflected in the "
            "server response without encoding, enabling phishing or UI redress."
        ),
        "remediation": (
            "HTML-encode all user input before embedding in HTML responses. "
            "Use template engines with auto-escaping enabled."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return f'<div>Hello {user_input}</div>'",
                "fixed": "from markupsafe import escape; return f'<div>Hello {escape(user_input)}</div>'",
            },
            "javascript": {
                "vulnerable": "res.send(`<div>Hello ${userInput}</div>`)",
                "fixed": "const escapeHtml = require('escape-html'); res.send(`<div>Hello ${escapeHtml(userInput)}</div>`)",
            },
            "php": {
                "vulnerable": "echo '<div>Hello ' . $_GET['name'] . '</div>';",
                "fixed": "echo '<div>Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</div>';",
            },
            "java": {
                "vulnerable": "out.println(\"<div>Hello \" + input + \"</div>\");",
                "fixed": "out.println(\"<div>Hello \" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(input) + \"</div>\");",
            },
            "csharp": {
                "vulnerable": "Response.Write($\"<div>Hello {input}</div>\");",
                "fixed": "Response.Write($\"<div>Hello {System.Net.WebUtility.HtmlEncode(input)}</div>\");",
            },
            "go": {
                "vulnerable": "fmt.Fprintf(w, \"<div>Hello %s</div>\", input)",
                "fixed": "fmt.Fprintf(w, \"<div>Hello %s</div>\", html.EscapeString(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (<script|<iframe|<object|<embed|<form|<input|<img|<svg|<math|<base|<meta|<link|<applet|<body|<html|<head|<style|javascript:|vbscript:|data:)\" \"id:1060,phase:2,deny,status:403,log,msg:'HTML Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/HTML_Injection",
        ],
    },

    "html_injection_stored": {
        "title": "Stored HTML Injection",
        "description": (
            "Attacker stores malicious HTML in the database (comments, profiles, "
            "posts) that is rendered to other users without encoding."
        ),
        "remediation": (
            "Apply output encoding consistently. Use rich-text sanitizers "
            "(DOMPurify, bleach) for allowed HTML. Encode at the template layer."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return render_template_string(f'<p>{stored_comment}</p>')",
                "fixed": "import bleach; return render_template_string(f'<p>{bleach.clean(stored_comment)}</p>')",
            },
            "javascript": {
                "vulnerable": "element.innerHTML = storedComment;",
                "fixed": "element.textContent = storedComment; // or use DOMPurify.sanitize(storedComment)",
            },
            "php": {
                "vulnerable": "echo '<p>' . $stored_comment . '</p>';",
                "fixed": "echo '<p>' . htmlspecialchars($stored_comment, ENT_QUOTES, 'UTF-8') . '</p>';",
            },
            "java": {
                "vulnerable": "out.println(\"<p>\" + storedComment + \"</p>\");",
                "fixed": "out.println(\"<p>\" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(storedComment) + \"</p>\");",
            },
            "csharp": {
                "vulnerable": "Response.Write($\"<p>{storedComment}</p>\");",
                "fixed": "Response.Write($\"<p>{System.Net.WebUtility.HtmlEncode(storedComment)}</p>\");",
            },
            "go": {
                "vulnerable": "fmt.Fprintf(w, \"<p>%s</p>\", storedComment)",
                "fixed": "fmt.Fprintf(w, \"<p>%s</p>\", html.EscapeString(storedComment))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (<script|<iframe|javascript:|on[a-z]+\\s*=)\" \"id:1061,phase:2,deny,status:403,log,msg:'Stored HTML Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    "html_injection_attribute": {
        "title": "Attribute Injection in HTML",
        "description": (
            "Attacker breaks out of an HTML attribute context by injecting "
            "quotes and additional attributes (onclick, onmouseover, href)."
        ),
        "remediation": (
            "URL-encode values in href/src attributes. HTML-encode all attribute "
            "values. Validate attribute values against strict patterns."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "f'<a href=\"{user_url}\">Link</a>'",
                "fixed": "f'<a href=\"{markupsafe.escape(user_url)}\">Link</a>'",
            },
            "javascript": {
                "vulnerable": "`<a href=\"${userUrl}\">Link</a>`",
                "fixed": "`<a href=\"${escapeHtml(userUrl)}\">Link</a>`",
            },
            "php": {
                "vulnerable": "'<a href=\"' . $_GET['url'] . '\">Link</a>'",
                "fixed": "'<a href=\"' . htmlspecialchars($_GET['url'], ENT_QUOTES) . '\">Link</a>'",
            },
            "java": {
                "vulnerable": "\"<a href=\\\"\" + input + \"\\\">Link</a>\"",
                "fixed": "\"<a href=\\\"\" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(input) + \"\\\">Link</a>\"",
            },
            "csharp": {
                "vulnerable": "$\"<a href=\\\"{input}\\\">Link</a>\"",
                "fixed": "$\"<a href=\\\"{System.Net.WebUtility.HtmlEncode(input)}\\\">Link</a>\"",
            },
            "go": {
                "vulnerable": "fmt.Sprintf(\"<a href=\\\"%s\\\">Link</a>\", input)",
                "fixed": "fmt.Sprintf(\"<a href=\\\"%s\\\">Link</a>\", html.EscapeString(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx ('|\\\")\\s+(onclick|onmouseover|onfocus|onblur|onload|onerror|href|src|action)\\s*=\" \"id:1062,phase:2,deny,status:403,log,msg:'HTML Attribute Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    # ─── XSS ────────────────────────────────────────────────────────────────

    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "description": (
            "Attacker crafts a URL with malicious JavaScript that executes "
            "when the victim clicks the link and the server reflects the input."
        ),
        "remediation": (
            "Apply context-aware output encoding. Use Content-Security-Policy headers. "
            "Enable template auto-escaping. Validate and sanitize input."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return f'Search results for: {request.args.get(\"q\")}'",
                "fixed": "from markupsafe import escape; return f'Search results for: {escape(request.args.get(\"q\"))}'",
            },
            "javascript": {
                "vulnerable": "res.send(`Search results for: ${req.query.q}`)",
                "fixed": "const escapeHtml = require('escape-html'); res.send(`Search results for: ${escapeHtml(req.query.q)}`)",
            },
            "php": {
                "vulnerable": "echo 'Search results for: ' . $_GET['q'];",
                "fixed": "echo 'Search results for: ' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');",
            },
            "java": {
                "vulnerable": "out.println(\"Search results for: \" + request.getParameter(\"q\"));",
                "fixed": "out.println(\"Search results for: \" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(request.getParameter(\"q\")));",
            },
            "csharp": {
                "vulnerable": "Response.Write($\"Search results for: {Request.QueryString[\"q\"]}\");",
                "fixed": "Response.Write($\"Search results for: {System.Net.WebUtility.HtmlEncode(Request.QueryString[\"q\"])}\");",
            },
            "go": {
                "vulnerable": "fmt.Fprintf(w, \"Search results for: %s\", r.URL.Query().Get(\"q\"))",
                "fixed": "fmt.Fprintf(w, \"Search results for: %s\", html.EscapeString(r.URL.Query().Get(\"q\")))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (<script[^>]*>|javascript:|on[a-z]+\\s*=|expression\\()\" \"id:1070,phase:2,deny,status:403,log,msg:'Reflected XSS Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    },

    "xss_stored": {
        "title": "Stored Cross-Site Scripting (XSS)",
        "description": (
            "Attacker stores malicious JavaScript in the application database "
            "(comments, profile fields) that executes in victims' browsers."
        ),
        "remediation": (
            "Apply output encoding at the template layer. Use CSP headers. "
            "Sanitize rich text with DOMPurify or bleach. Validate all input."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return render_template_string(f'<p>{comment}</p>')",
                "fixed": "import bleach; return render_template_string(f'<p>{bleach.clean(comment, tags=[\"p\",\"b\",\"i\"])}</p>')",
            },
            "javascript": {
                "vulnerable": "element.innerHTML = comment;",
                "fixed": "element.textContent = comment;",
            },
            "php": {
                "vulnerable": "echo '<p>' . $comment . '</p>';",
                "fixed": "echo '<p>' . htmlspecialchars($comment, ENT_QUOTES, 'UTF-8') . '</p>';",
            },
            "java": {
                "vulnerable": "out.println(\"<p>\" + comment + \"</p>\");",
                "fixed": "out.println(\"<p>\" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(comment) + \"</p>\");",
            },
            "csharp": {
                "vulnerable": "Response.Write($\"<p>{comment}</p>\");",
                "fixed": "Response.Write($\"<p>{System.Net.WebUtility.HtmlEncode(comment)}</p>\");",
            },
            "go": {
                "vulnerable": "fmt.Fprintf(w, \"<p>%s</p>\", comment)",
                "fixed": "fmt.Fprintf(w, \"<p>%s</p>\", html.EscapeString(comment))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx <script|javascript:|on[a-z]+\\s*=|alert\\(|confirm\\(|prompt\\(\" \"id:1071,phase:2,deny,status:403,log,msg:'Stored XSS Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    "xss_dom_based": {
        "title": "DOM-based Cross-Site Scripting (XSS)",
        "description": (
            "Attacker manipulates client-side JavaScript sources/sinks "
            "(document.location, innerHTML, eval) to execute arbitrary code."
        ),
        "remediation": (
            "Never use innerHTML with user data. Use textContent instead. "
            "Validate URL schemes. Apply CSP without unsafe-eval."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return '<script>var name = \"' + user_input + '\";</script>'",
                "fixed": "import json; return '<script>var name = ' + json.dumps(user_input) + ';</script>'",
            },
            "javascript": {
                "vulnerable": "element.innerHTML = location.hash.substring(1);",
                "fixed": "element.textContent = decodeURIComponent(location.hash.substring(1));",
            },
            "php": {
                "vulnerable": "echo '<script>var x = \"' . $_GET['val'] . '\";</script>';",
                "fixed": "echo '<script>var x = ' . json_encode($_GET['val']) . ';</script>';",
            },
            "java": {
                "vulnerable": "out.println(\"<script>var x = \\\"\" + input + \"\\\";</script>\");",
                "fixed": "out.println(\"<script>var x = \" + org.apache.commons.text.StringEscapeUtils.escapeJson(input) + \";</script>\");",
            },
            "csharp": {
                "vulnerable": "Response.Write($\"<script>var x = \\\"{input}\\\";</script>\");",
                "fixed": "Response.Write($\"<script>var x = {System.Text.Json.JsonSerializer.Serialize(input)};</script>\");",
            },
            "go": {
                "vulnerable": "fmt.Fprintf(w, \"<script>var x = \\\"%s\\\";</script>\", input)",
                "fixed": "b, _ := json.Marshal(input); fmt.Fprintf(w, \"<script>var x = %s;</script>\", b)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (document\\.cookie|document\\.URL|document\\.referrer|window\\.location)\" \"id:1072,phase:2,deny,status:403,log,msg:'DOM XSS Source Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
        ],
    },

    # ─── SSTI ───────────────────────────────────────────────────────────────

    "ssti_jinja2": {
        "title": "Jinja2 Server-Side Template Injection",
        "description": (
            "Attacker injects Jinja2 template directives ({% %}, {{ }}) "
            "that are evaluated server-side, leading to RCE via config or os modules."
        ),
        "remediation": (
            "Never render user input as template code. Use render_template_string "
            "with auto-escaping. Use SandboxedEnvironment. Apply least-privilege."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "render_template_string(f'Hello {user_input}')",
                "fixed": "render_template_string('Hello {{ name }}', name=user_input)",
            },
            "javascript": {
                "vulnerable": "nunjucks.renderString(`Hello ${userInput}`, {})",
                "fixed": "nunjucks.renderString('Hello {{ name }}', {name: userInput})",
            },
            "php": {
                "vulnerable": "$twig->render('index.twig', ['input' => $_GET['name']]); // with {{ input|raw }}",
                "fixed": "$twig->render('index.twig', ['input' => $_GET['name']]); // with {{ input }} (auto-escaped)",
            },
            "java": {
                "vulnerable": "Velocity.evaluate(context, writer, \"log\", userInput);",
                "fixed": "Velocity.evaluate(context, writer, \"log\", \"$input\"); context.put(\"input\", userInput);",
            },
            "csharp": {
                "vulnerable": "RazorEngine.Engine.Razor.RunCompile(template, \"key\", null, new {input = userInput});",
                "fixed": "RazorEngine.Engine.Razor.RunCompile(\"@Model.Input\", \"key\", null, new {Input = userInput});",
            },
            "go": {
                "vulnerable": "t.Execute(w, map[string]interface{}{\"name\": userInput})",
                "fixed": "t.Execute(w, map[string]interface{}{\"name\": html.EscapeString(userInput)})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\{\\{.*\\}\\}|\\{%.*%\\}|config|os\\.popen|__class__|__subclasses__)\" \"id:1080,phase:2,deny,status:403,log,msg:'SSTI Jinja2 Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
    },

    "ssti_freemarker": {
        "title": "FreeMarker Server-Side Template Injection",
        "description": (
            "Attacker injects FreeMarker directives (#{...}, <#assign>) "
            "to access Java objects and execute arbitrary code."
        ),
        "remediation": (
            "Use TemplateClassResolver to restrict access to dangerous classes. "
            "Never use .new() or object constructors in templates. "
            "Apply sandboxed configuration."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "template.render(user_input)",
                "fixed": "template.render({'name': user_input})",
            },
            "javascript": {
                "vulnerable": "freemarker.render(template, {input: userInput})",
                "fixed": "freemarker.render(template, {input: userInput}, {newBuiltinClassResolver: 'denied'})",
            },
            "php": {
                "vulnerable": "$tpl->assign('input', $_GET['name']); $tpl->display('template.tpl');",
                "fixed": "$tpl->assign('input', htmlspecialchars($_GET['name'])); $tpl->display('template.tpl');",
            },
            "java": {
                "vulnerable": "cfg.getTemplate(\"template.ftl\").process(dataModel, writer);",
                "fixed": "cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER); cfg.getTemplate(\"template.ftl\").process(dataModel, writer);",
            },
            "csharp": {
                "vulnerable": "TemplateEngine.Render(template, new { input = userInput });",
                "fixed": "TemplateEngine.Render(template, new { input = WebUtility.HtmlEncode(userInput) });",
            },
            "go": {
                "vulnerable": "tmpl.Execute(w, map[string]interface{}{\"input\": userInput})",
                "fixed": "tmpl.Execute(w, map[string]interface{}{\"input\": html.EscapeString(userInput)})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (#\\{|<#assign|<#list|objectConstructor|new\\()\" \"id:1081,phase:2,deny,status:403,log,msg:'FreeMarker SSTI Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/web-security/server-side-template-injection/freemarker",
        ],
    },

    "ssti_thymeleaf": {
        "title": "Thymeleaf Server-Side Template Injection",
        "description": (
            "Attacker injects Thymeleaf expressions (~{...}, [[...]]) "
            "to access Spring context objects and achieve RCE."
        ),
        "remediation": (
            "Use expression whitelist. Disable Spring EL evaluation in templates. "
            "Never pass user input as template selection variables."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "render(template, {'input': user_input})",
                "fixed": "render(template, {'input': user_input})  # Ensure template doesn't use unescaped expressions",
            },
            "javascript": {
                "vulnerable": "thymeleaf.render(template, {input: userInput})",
                "fixed": "thymeleaf.render(template, {input: escapeHtml(userInput)})",
            },
            "php": {
                "vulnerable": "$twig->render($template, ['input' => $_GET['val']]);",
                "fixed": "$twig->render($template, ['input' => htmlspecialchars($_GET['val'])]);",
            },
            "java": {
                "vulnerable": "TemplateEngine.process(\"template\", context, writer);",
                "fixed": "TemplateEngine engine = new TemplateEngine(); engine.setDialectPrefix(null); engine.process(\"template\", context, writer);",
            },
            "csharp": {
                "vulnerable": "RazorEngine.Engine.Razor.RunCompile(template, \"key\", null, new {input});",
                "fixed": "RazorEngine.Engine.Razor.RunCompile(template, \"key\", null, new {input = WebUtility.HtmlEncode(input)});",
            },
            "go": {
                "vulnerable": "tmpl.Execute(w, data)",
                "fixed": "tmpl.Execute(w, data) // Use html/template which auto-escapes",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (~\\{|\\[\\[|\\$\\{|T\\(|new\\(|java\\.lang\\.Runtime)\" \"id:1082,phase:2,deny,status:403,log,msg:'Thymeleaf SSTI Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://www.thymeleaf.org/doc/articles/safehtml.html",
        ],
    },

    "ssti_pebble": {
        "title": "Pebble Server-Side Template Injection",
        "description": (
            "Attacker injects Pebble template expressions to access "
            "Java objects and execute arbitrary code."
        ),
        "remediation": (
            "Apply sandboxed PebbleEngine configuration. Restrict available "
            "functions and filters. Never render user input as template code."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "render(template, {'input': user_input})",
                "fixed": "render(template, {'input': user_input})  # Use auto-escaping in Pebble",
            },
            "javascript": {
                "vulnerable": "pebble.render(template, {input: userInput})",
                "fixed": "pebble.render(template, {input: escapeHtml(userInput)})",
            },
            "php": {
                "vulnerable": "$twig->render($template, ['input' => $_GET['name']]);",
                "fixed": "$twig->render($template, ['input' => htmlspecialchars($_GET['name'])]);",
            },
            "java": {
                "vulnerable": "PebbleEngine engine = new PebbleEngine.Builder().build(); engine.getTemplate(name).evaluate(writer);",
                "fixed": "PebbleEngine engine = new PebbleEngine.Builder().loader(new StringLoader()).strictVariables(false).build();",
            },
            "csharp": {
                "vulnerable": "var result = template.Render(model);",
                "fixed": "var result = template.Render(model); // Use Scriban with auto-escape",
            },
            "go": {
                "vulnerable": "tmpl.Execute(w, data)",
                "fixed": "tmpl.Execute(w, data) // Use html/template for auto-escaping",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\{\\{.*\\}\\}|getRuntime|exec|Runtime\\.getRuntime)\" \"id:1083,phase:2,deny,status:403,log,msg:'Pebble SSTI Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/1336.html",
        ],
    },

    # ─── CRLF INJECTION ─────────────────────────────────────────────────────

    "crlf_injection_response_splitting": {
        "title": "HTTP Response Splitting via CRLF Injection",
        "description": (
            "Attacker injects CRLF characters (%0d%0a) into HTTP headers "
            "to split the response, enabling cache poisoning and XSS."
        ),
        "remediation": (
            "Filter CR/LF characters from all user input used in HTTP headers. "
            "Use framework-provided header-setting APIs. Validate header values."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "response.headers['Location'] = user_input",
                "fixed": "response.headers['Location'] = user_input.replace('\\r', '').replace('\\n', '')",
            },
            "javascript": {
                "vulnerable": "res.setHeader('Location', userInput);",
                "fixed": "res.setHeader('Location', userInput.replace(/[\\r\\n]/g, ''));",
            },
            "php": {
                "vulnerable": "header('Location: ' . $_GET['redirect']);",
                "fixed": "header('Location: ' . preg_replace('/[\\r\\n]/', '', $_GET['redirect']));",
            },
            "java": {
                "vulnerable": "response.setHeader(\"Location\", input);",
                "fixed": "response.setHeader(\"Location\", input.replaceAll(\"[\\r\\n]\", \"\"));",
            },
            "csharp": {
                "vulnerable": "Response.Headers[\"Location\"] = input;",
                "fixed": "Response.Headers[\"Location\"] = Regex.Replace(input, @\"[\\r\\n]\", \"\");",
            },
            "go": {
                "vulnerable": "w.Header().Set(\"Location\", input)",
                "fixed": "w.Header().Set(\"Location\", strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%0[da]|\\r|\\n)\" \"id:1090,phase:2,deny,status:403,log,msg:'CRLF Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
        ],
    },

    "crlf_injection_log_injection": {
        "title": "Log Injection via CRLF",
        "description": (
            "Attacker injects newlines into log entries to forge log entries "
            "or inject additional log lines."
        ),
        "remediation": (
            "Sanitize user input before writing to logs. Encode newlines. "
            "Use structured logging (JSON format)."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "logging.info(f'User login: {username}')",
                "fixed": "logging.info('User login: %s', username.replace('\\n', '_').replace('\\r', '_'))",
            },
            "javascript": {
                "vulnerable": "logger.info(`User login: ${username}`);",
                "fixed": "logger.info('User login: %s', username.replace(/[\\r\\n]/g, '_'));",
            },
            "php": {
                "vulnerable": "error_log('User login: ' . $_GET['user']);",
                "fixed": "error_log('User login: ' . preg_replace('/[\\r\\n]/', '_', $_GET['user']));",
            },
            "java": {
                "vulnerable": "logger.info(\"User login: \" + input);",
                "fixed": "logger.info(\"User login: {}\", input.replaceAll(\"[\\r\\n]\", \"_\"));",
            },
            "csharp": {
                "vulnerable": "logger.LogInformation($\"User login: {input}\");",
                "fixed": "logger.LogInformation($\"User login: {Regex.Replace(input, @\"[\\r\\n]\", \"_\")}\");",
            },
            "go": {
                "vulnerable": "log.Printf(\"User login: %s\", input)",
                "fixed": "log.Printf(\"User login: %s\", strings.NewReplacer(\"\\r\", \"_\", \"\\n\", \"_\").Replace(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%0[da]|\\r|\\n).*log\" \"id:1091,phase:2,deny,status:403,log,msg:'Log Injection via CRLF Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/117.html",
        ],
    },

    # ─── HEADER INJECTION ───────────────────────────────────────────────────

    "header_injection_host_header": {
        "title": "Host Header Injection",
        "description": (
            "Attacker manipulates the Host header to poison cache, reset "
            "passwords, or exploit routing logic."
        ),
        "remediation": (
            "Validate Host header against a whitelist of allowed domains. "
            "Configure web server to reject requests with unrecognized Host headers."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "host = request.headers.get('Host')",
                "fixed": "host = request.headers.get('Host'); assert host in ALLOWED_HOSTS",
            },
            "javascript": {
                "vulnerable": "const host = req.headers.host;",
                "fixed": "const host = req.headers.host; if (!ALLOWED_HOSTS.includes(host)) return res.status(403).end();",
            },
            "php": {
                "vulnerable": "$host = $_SERVER['HTTP_HOST'];",
                "fixed": "$host = $_SERVER['HTTP_HOST']; if (!in_array($host, $ALLOWED_HOSTS)) { http_response_code(403); exit; }",
            },
            "java": {
                "vulnerable": "String host = request.getHeader(\"Host\");",
                "fixed": "String host = request.getHeader(\"Host\"); if (!ALLOWED_HOSTS.contains(host)) { response.setStatus(403); return; }",
            },
            "csharp": {
                "vulnerable": "var host = Request.Host.Value;",
                "fixed": "if (!ALLOWED_HOSTS.Contains(Request.Host.Value)) { Response.StatusCode = 403; return; }",
            },
            "go": {
                "vulnerable": "host := r.Host",
                "fixed": "if !allowedHosts[r.Host] { http.Error(w, \"Forbidden\", 403); return }",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_HEADERS:Host \"@rx (localhost|127\\.0\\.0\\.1|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)\" \"id:1100,phase:1,deny,status:403,log,msg:'Host Header Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/644.html",
        ],
    },

    "header_injection_x_forwarded": {
        "title": "X-Forwarded-For Header Injection",
        "description": (
            "Attacker spoofs X-Forwarded-For header to bypass IP-based "
            "access controls or poisoning logs."
        ),
        "remediation": (
            "Only trust proxy-added headers from configured reverse proxies. "
            "Use trusted proxy middleware. Never use X-Forwarded-For for auth."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "ip = request.headers.get('X-Forwarded-For')",
                "fixed": "ip = request.remote_addr  # Use only direct connection IP",
            },
            "javascript": {
                "vulnerable": "const ip = req.headers['x-forwarded-for'];",
                "fixed": "const ip = req.socket.remoteAddress;",
            },
            "php": {
                "vulnerable": "$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];",
                "fixed": "$ip = $_SERVER['REMOTE_ADDR'];",
            },
            "java": {
                "vulnerable": "String ip = request.getHeader(\"X-Forwarded-For\");",
                "fixed": "String ip = request.getRemoteAddr();",
            },
            "csharp": {
                "vulnerable": "var ip = Request.Headers[\"X-Forwarded-For\"].FirstOrDefault();",
                "fixed": "var ip = HttpContext.Connection.RemoteIpAddress?.ToString();",
            },
            "go": {
                "vulnerable": "ip := r.Header.Get(\"X-Forwarded-For\")",
                "fixed": "ip, _, _ := net.SplitHostPort(r.RemoteAddr)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_HEADERS:X-Forwarded-For \"@rx ^\\d+\\.\\d+\\.\\d+\\.\\d+$\" \"id:1101,phase:1,pass,nolog,tag:'IP Spoofing Check'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/644.html",
        ],
    },

    # ─── LOG INJECTION ──────────────────────────────────────────────────────

    "log_injection_log forging": {
        "title": "Log Forging / Injection",
        "description": (
            "Attacker injects content into log files to forge entries, "
            "obfuscate attacks, or trigger log analysis vulnerabilities."
        ),
        "remediation": (
            "Sanitize all user input before writing to logs. Replace control "
            "characters. Use structured logging (JSON). Validate log entry format."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "logging.info(f'Request from {user_input}')",
                "fixed": "import re; sanitized = re.sub(r'[\\r\\n]', '_', user_input); logging.info('Request from %s', sanitized)",
            },
            "javascript": {
                "vulnerable": "logger.info(`Request from ${userInput}`);",
                "fixed": "const safe = userInput.replace(/[\\r\\n]/g, '_'); logger.info('Request from %s', safe);",
            },
            "php": {
                "vulnerable": "error_log('Request from ' . $_GET['user']);",
                "fixed": "error_log('Request from ' . preg_replace('/[\\r\\n]/', '_', $_GET['user']));",
            },
            "java": {
                "vulnerable": "logger.info(\"Request from \" + input);",
                "fixed": "logger.info(\"Request from {}\", input.replaceAll(\"[\\r\\n]\", \"_\"));",
            },
            "csharp": {
                "vulnerable": "logger.LogInformation($\"Request from {input}\");",
                "fixed": "logger.LogInformation($\"Request from {Regex.Replace(input, @\"[\\r\\n]\", \"_\")}\");",
            },
            "go": {
                "vulnerable": "log.Printf(\"Request from %s\", input)",
                "fixed": "log.Printf(\"Request from %s\", strings.NewReplacer(\"\\r\", \"_\", \"\\n\", \"_\").Replace(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%0[da]|\\r|\\n)\" \"id:1110,phase:2,deny,status:403,log,msg:'Log Injection Attempt Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/117.html",
        ],
    },

    "log_injection_injection_through_logs": {
        "title": "Injection Through Log Analysis",
        "description": (
            "Attacker crafts log entries that exploit vulnerabilities in log "
            "viewing tools (ANSI escape codes, XSS in web-based log viewers)."
        ),
        "remediation": (
            "Strip ANSI escape codes from log output. Encode log entries in "
            "web viewers. Use safe log rendering libraries."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "logging.info(f'User action: {user_input}')",
                "fixed": "import re; safe = re.sub(r'\\x1b\\[[0-9;]*m', '', user_input); logging.info('User action: %s', safe)",
            },
            "javascript": {
                "vulnerable": "logger.info(`User action: ${userInput}`);",
                "fixed": "const safe = userInput.replace(/\\x1b\\[[0-9;]*m/g, ''); logger.info('User action: %s', safe);",
            },
            "php": {
                "vulnerable": "error_log('User action: ' . $_GET['action']);",
                "fixed": "error_log('User action: ' . preg_replace('/\\x1b\\[[0-9;]*m/', '', $_GET['action']));",
            },
            "java": {
                "vulnerable": "logger.info(\"User action: \" + input);",
                "fixed": "logger.info(\"User action: {}\", input.replaceAll(\"\\\\x1b\\\\[[0-9;]*m\", \"\"));",
            },
            "csharp": {
                "vulnerable": "logger.LogInformation($\"User action: {input}\");",
                "fixed": "logger.LogInformation($\"User action: {Regex.Replace(input, @\"\\x1b\\[[0-9;]*m\", \"\")}\");",
            },
            "go": {
                "vulnerable": "log.Printf(\"User action: %s\", input)",
                "fixed": "re := regexp.MustCompile(`\\x1b\\[[0-9;]*m`); log.Printf(\"User action: %s\", re.ReplaceAllString(input, \"\"))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx \\x1b\\[[0-9;]*m\" \"id:1111,phase:2,deny,status:403,log,msg:'ANSI Escape Code Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/117.html",
        ],
    },

    # ─── EL INJECTION ───────────────────────────────────────────────────────

    "el_injection_spring": {
        "title": "Spring Expression Language (SpEL) Injection",
        "description": (
            "Attacker injects SpEL expressions into Spring-based applications "
            "to access arbitrary objects and achieve RCE."
        ),
        "remediation": (
            "Use SimpleEvaluationContext instead of StandardEvaluationContext. "
            "Apply expression whitelist. Disable dangerous methods."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "render(template, {'input': user_input})",
                "fixed": "render(template, {'input': user_input})  # Use Jinja2 auto-escaping",
            },
            "javascript": {
                "vulnerable": "eval(userInput);",
                "fixed": "// Never use eval. Use JSON.parse() for data, or a safe expression parser.",
            },
            "php": {
                "vulnerable": "eval($_GET['expr']);",
                "fixed": "echo htmlspecialchars($_GET['expr']); // Never eval user input",
            },
            "java": {
                "vulnerable": "SpelExpressionParser parser = new SpelExpressionParser(); parser.parseExpression(input).getValue();",
                "fixed": "SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build(); parser.parseExpression(input, new TemplateParserContext()).getValue(ctx);",
            },
            "csharp": {
                "vulnerable": "new Expression evaluator(input).Evaluate();",
                "fixed": "var options = new EvaluateOptions { AllowReflection = false }; new Expression(input).Evaluate(options);",
            },
            "go": {
                "vulnerable": "expr.Eval(input, env)",
                "fixed": "expr.Eval(input, env) // Use expr-lang/expr with restricted functions",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (T\\(|getRuntime|exec|java\\.lang\\.)\" \"id:1120,phase:2,deny,status:403,log,msg:'SpEL Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/917.html",
            "https://docs.spring.io/spring-framework/reference/core/expressions.html",
        ],
    },

    "el_injection_ognl": {
        "title": "OGNL Injection (Apache Struts)",
        "description": (
            "Attacker injects OGNL expressions into Struts-based applications "
            "to achieve remote code execution."
        ),
        "remediation": (
            "Apply strict parameter name whitelist. Use Struts 2.5+ with "
            "parameter injection disabled. Update to latest Struts version."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "eval(request.form.get('expression'))",
                "fixed": "# Never evaluate user expressions",
            },
            "javascript": {
                "vulnerable": "eval(req.body.expression);",
                "fixed": "// Never use eval on user input",
            },
            "php": {
                "vulnerable": "eval($_POST['expression']);",
                "fixed": "// Never use eval on user input",
            },
            "java": {
                "vulnerable": "Ognl.getValue(input, context);",
                "fixed": "Use parameter whitelist: String[] allowed = {\"name\", \"email\"}; if (!Arrays.asList(allowed).contains(paramName)) reject();",
            },
            "csharp": {
                "vulnerable": "OgnlContext context = new OgnlContext(); Ognl.getValue(input, context);",
                "fixed": "Use a parameter whitelist to validate all input parameter names",
            },
            "go": {
                "vulnerable": "// Not typically applicable in Go",
                "fixed": "Validate all input parameter names against an allowlist",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\#context|\\#request|\\#session|\\#application|getRuntime|exec)\" \"id:1121,phase:2,deny,status:403,log,msg:'OGNL Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/917.html",
            "https://cwiki.apache.org/confluence/display/WW/S2-045",
        ],
    },

    "el_injection_javascript": {
        "title": "JavaScript eval() Injection",
        "description": (
            "Attacker injects JavaScript code into eval(), Function(), "
            "setTimeout(), or setInterval() calls."
        ),
        "remediation": (
            "Never use eval() with user input. Use JSON.parse() for data "
            "deserialization. Use function constructors instead of eval."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "eval(user_input)",
                "fixed": "import ast; ast.literal_eval(user_input)  # For safe data parsing",
            },
            "javascript": {
                "vulnerable": "eval(userInput);",
                "fixed": "const data = JSON.parse(userInput); // Never use eval on user input",
            },
            "php": {
                "vulnerable": "eval($_GET['code']);",
                "fixed": "// Never use eval on user input. Use a safe expression evaluator.",
            },
            "java": {
                "vulnerable": "ScriptEngineManager mgr = new ScriptEngineManager(); mgr.getEngineByName(\"JavaScript\").eval(input);",
                "fixed": "// Never use ScriptEngine.eval() with user input",
            },
            "csharp": {
                "vulnerable": "new CSharpScript().EvaluateAsync(input).Result;",
                "fixed": "// Never evaluate C# code from user input",
            },
            "go": {
                "vulnerable": "// Not typically applicable in Go without goja",
                "fixed": "Use a sandboxed JavaScript engine if needed",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (eval\\(|new\\s+Function\\(|setTimeout\\(|setInterval\\()\" \"id:1122,phase:2,deny,status:403,log,msg:'JavaScript eval Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/95.html",
        ],
    },

    # ─── ADDITIONAL SUB-TYPES ───────────────────────────────────────────────

    "header_injection_content_type": {
        "title": "Content-Type Header Injection",
        "description": (
            "Attacker manipulates Content-Type header to trigger XSS "
            "via MIME type confusion."
        ),
        "remediation": (
            "Validate and fix Content-Type headers. Use X-Content-Type-Options: nosniff. "
            "Never rely on user-controlled Content-Type for rendering."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "response.headers['Content-Type'] = request.args.get('type')",
                "fixed": "response.headers['Content-Type'] = 'text/html; charset=utf-8'",
            },
            "javascript": {
                "vulnerable": "res.setHeader('Content-Type', req.query.type);",
                "fixed": "res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.setHeader('X-Content-Type-Options', 'nosniff');",
            },
            "php": {
                "vulnerable": "header('Content-Type: ' . $_GET['type']);",
                "fixed": "header('Content-Type: text/html; charset=utf-8'); header('X-Content-Type-Options: nosniff');",
            },
            "java": {
                "vulnerable": "response.setContentType(request.getParameter(\"type\"));",
                "fixed": "response.setContentType(\"text/html; charset=UTF-8\"); response.setHeader(\"X-Content-Type-Options\", \"nosniff\");",
            },
            "csharp": {
                "vulnerable": "Response.ContentType = Request.Query[\"type\"].ToString();",
                "fixed": "Response.ContentType = \"text/html; charset=utf-8\"; Response.Headers[\"X-Content-Type-Options\"] = \"nosniff\";",
            },
            "go": {
                "vulnerable": "w.Header().Set(\"Content-Type\", r.URL.Query().Get(\"type\"))",
                "fixed": "w.Header().Set(\"Content-Type\", \"text/html; charset=utf-8\"); w.Header().Set(\"X-Content-Type-Options\", \"nosniff\")",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_HEADERS:Content-Type \"@rx (text/html|application/x-javascript|application/javascript)\" \"id:1130,phase:1,deny,status:403,log,msg:'Content-Type Header Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/644.html",
        ],
    },

    "crlf_injection_mail_header": {
        "title": "Email Header Injection via CRLF",
        "description": (
            "Attacker injects CRLF characters into email headers "
            "(Subject, From, To) to add arbitrary headers or recipients."
        ),
        "remediation": (
            "Filter CR/LF characters from all email header fields. "
            "Use mail library APIs that handle header encoding."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "msg['Subject'] = user_input",
                "fixed": "msg['Subject'] = user_input.replace('\\r', '').replace('\\n', '')",
            },
            "javascript": {
                "vulnerable": "transport.sendMail({subject: userInput});",
                "fixed": "transport.sendMail({subject: userInput.replace(/[\\r\\n]/g, '')});",
            },
            "php": {
                "vulnerable": "mail($to, $_GET['subject'], $body);",
                "fixed": "mail($to, preg_replace('/[\\r\\n]/', '', $_GET['subject']), $body);",
            },
            "java": {
                "vulnerable": "message.setSubject(input);",
                "fixed": "message.setSubject(input.replaceAll(\"[\\r\\n]\", \"\"));",
            },
            "csharp": {
                "vulnerable": "mailMessage.Subject = input;",
                "fixed": "mailMessage.Subject = input.Replace(\"\\r\", \"\").Replace(\"\\n\", \"\");",
            },
            "go": {
                "vulnerable": "msg.SetHeader(\"Subject\", input)",
                "fixed": "msg.SetHeader(\"Subject\", strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%0[da]|\\r|\\n).*(subject|from|to|cc|bcc)\" \"id:1131,phase:2,deny,status:403,log,msg:'Email Header Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/113.html",
        ],
    },

    "xpath_injection_error_based": {
        "title": "XPath Error-based Injection",
        "description": (
            "Attacker uses XPath functions that generate errors to extract "
            "information from XML documents via error messages."
        ),
        "remediation": (
            "Use parameterized XPath queries. Suppress detailed error messages. "
            "Validate input against XPath-safe character sets."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "tree.xpath(f\"//user[name='{user}']\")",
                "fixed": "tree.xpath('//user[name=$name]', name=user)",
            },
            "javascript": {
                "vulnerable": "xpath.select(`//user[name='${user}']`)",
                "fixed": "xpath.select('//user[name=$name]', {name: user})",
            },
            "php": {
                "vulnerable": "$xp->query(\"//user[name='\" . $_GET['name'] . \"']\");",
                "fixed": "$safe = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['name']); $xp->query(\"//user[name='\" . $safe . \"']\");",
            },
            "java": {
                "vulnerable": "XPathExpression expr = xp.compile(\"//user[name='\" + name + \"']\");",
                "fixed": "XPathExpression expr = xp.compile(\"//user[name=$n]\"); expr.evaluate(doc, new SimpleVariableResolver(Map.of(\"$n\", name)));",
            },
            "csharp": {
                "vulnerable": "doc.SelectNodes($\"//user[name='{name}']\");",
                "fixed": "doc.SelectNodes($\"//user[name='{SanitizeXPath(name)}']\");",
            },
            "go": {
                "vulnerable": "xmlquery.QueryAll(doc, fmt.Sprintf(\"//user[name='%s']\", name))",
                "fixed": "xmlquery.QueryAll(doc, \"//user[name='' and string-length(name)=0]\")",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (extract-value|updatexml|exp\\()\" \"id:1140,phase:2,deny,status:403,log,msg:'XPath Error-based Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/91.html",
        ],
    },

    "nosql_injection_mongodb_aggregation": {
        "title": "MongoDB Aggregation Pipeline Injection",
        "description": (
            "Attacker injects operators into MongoDB aggregation pipeline "
            "stages to manipulate data processing."
        ),
        "remediation": (
            "Validate and sanitize all pipeline stage inputs. Use strict "
            "schema validation for aggregation queries."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "db.users.aggregate([{'$match': {'username': request.json['username']}}])",
                "fixed": "db.users.aggregate([{'$match': {'username': str(request.json['username'])}}])",
            },
            "javascript": {
                "vulnerable": "db.users.aggregate([{$match: {username: req.body.username}}])",
                "fixed": "db.users.aggregate([{$match: {username: String(req.body.username)}}])",
            },
            "php": {
                "vulnerable": "$collection->aggregate([['\\$match' => ['username' => $_POST['user']]]]);",
                "fixed": "$collection->aggregate([['\\$match' => ['username' => (string)$_POST['user']]]]);",
            },
            "java": {
                "vulnerable": "collection.aggregate(List.of(Aggregates.match(Filters.eq(\"username\", input))));",
                "fixed": "collection.aggregate(List.of(Aggregates.match(Filters.eq(\"username\", input.toString()))));",
            },
            "csharp": {
                "vulnerable": "collection.Aggregate(new BsonDocumentPipelineStageDefinition<BsonDocument>(pipeline));",
                "fixed": "collection.Aggregate(new BsonDocumentPipelineStageDefinition<BsonDocument>(\"{\\$match: {username: '\" + input.ToString() + \"'}}\"));",
            },
            "go": {
                "vulnerable": "collection.Aggregate(ctx, mongo.Pipeline{{{\"\\$match\", bson.M{\"username\": input}}}})",
                "fixed": "collection.Aggregate(ctx, mongo.Pipeline{{{\"\\$match\", bson.M{\"username\": fmt.Sprintf(\"%v\", input)}}}})",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule REQUEST_BODY \"@rx \\$group|\\$unwind|\\$lookup|\\$merge|\\$out\" \"id:1141,phase:2,deny,status:403,log,msg:'MongoDB Aggregation Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/943.html",
        ],
    },

    "sql_injection_information_schema": {
        "title": "SQL Injection – Information Schema Enumeration",
        "description": (
            "Attacker uses INFORMATION_SCHEMA queries to enumerate database "
            "structure before extracting sensitive data."
        ),
        "remediation": (
            "Use parameterized queries. Restrict database account permissions. "
            "Block access to system tables."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "cursor.execute(f\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES\")",
                "fixed": "cursor.execute(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = %s\", (schema,))",
            },
            "javascript": {
                "vulnerable": "db.query('SELECT table_name FROM INFORMATION_SCHEMA.TABLES')",
                "fixed": "db.query('SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = ?', [schema])",
            },
            "php": {
                "vulnerable": "mysqli_query($conn, 'SELECT table_name FROM INFORMATION_SCHEMA.TABLES');",
                "fixed": "$stmt = $conn->prepare('SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = ?'); $stmt->bind_param('s', $schema); $stmt->execute();",
            },
            "java": {
                "vulnerable": "stmt.executeQuery(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES\");",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = ?\"); ps.setString(1, schema); ps.executeQuery();",
            },
            "csharp": {
                "vulnerable": "new SqlCommand(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES\", conn).ExecuteReader();",
                "fixed": "var cmd = new SqlCommand(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = @schema\", conn); cmd.Parameters.AddWithValue(\"@schema\", schema); cmd.ExecuteReader();",
            },
            "go": {
                "vulnerable": "db.Query(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES\")",
                "fixed": "db.Query(\"SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = ?\", schema)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (INFORMATION_SCHEMA|SYS\\.TABLES|SYSOBJECTS|SYS\\.USER_TABLES)\" \"id:1142,phase:2,deny,status:403,log,msg:'SQL Schema Enumeration Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },

    "os_command_injection_path_traversal_combo": {
        "title": "OS Command Injection + Path Traversal Combo",
        "description": (
            "Attacker combines path traversal with command injection to "
            "access arbitrary files and execute commands."
        ),
        "remediation": (
            "Use language-native file APIs. Never concatenate paths from user input. "
            "Use os.path.join() or Path.resolve() with validation."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "os.system(f'cat {user_input}')",
                "fixed": "from pathlib import Path; p = Path(user_input); if p.resolve().is_relative_to(Path('/safe/dir')): subprocess.run(['cat', str(p)])",
            },
            "javascript": {
                "vulnerable": "execSync(`cat ${userInput}`)",
                "fixed": "const safePath = path.resolve('/safe/dir', userInput); if (!safePath.startsWith('/safe/dir')) throw new Error('Invalid');",
            },
            "php": {
                "vulnerable": "exec('cat ' . $_GET['file']);",
                "fixed": "exec('cat ' . escapeshellarg(realpath('/safe/dir/' . $_GET['file'])));",
            },
            "java": {
                "vulnerable": "Runtime.getRuntime().exec(new String[]{'cat', input});",
                "fixed": "Path safe = Path.of(\"/safe/dir\").resolve(input).normalize(); if (!safe.startsWith(\"/safe/dir\")) throw new SecurityException();",
            },
            "csharp": {
                "vulnerable": "Process.Start(\"cat\", input);",
                "fixed": "var safe = Path.GetFullPath(Path.Combine(\"/safe/dir\", input)); if (!safe.StartsWith(\"/safe/dir\")) throw new SecurityException();",
            },
            "go": {
                "vulnerable": "exec.Command(\"cat\", input)",
                "fixed": "safe := filepath.Join(\"/safe/dir\", filepath.Clean(input)); if !strings.HasPrefix(safe, \"/safe/dir\") { return errors.New(\"invalid\") }",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (\\.\\./|\\.\\.\\\\|%2e%2e)\" \"id:1143,phase:2,deny,status:403,log,msg:'Path Traversal with Command Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },

    "header_injection_response_splitting": {
        "title": "Header Injection Leading to Response Splitting",
        "description": (
            "Attacker injects CRLF characters into response headers to "
            "split the HTTP response body."
        ),
        "remediation": (
            "Filter CR/LF from all header values. Use framework APIs for "
            "setting headers. Validate all user-controlled header data."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "response.headers['X-Custom'] = user_input",
                "fixed": "response.headers['X-Custom'] = user_input.replace('\\r', '').replace('\\n', '')",
            },
            "javascript": {
                "vulnerable": "res.setHeader('X-Custom', userInput);",
                "fixed": "res.setHeader('X-Custom', userInput.replace(/[\\r\\n]/g, ''));",
            },
            "php": {
                "vulnerable": "header('X-Custom: ' . $_GET['val']);",
                "fixed": "header('X-Custom: ' . preg_replace('/[\\r\\n]/', '', $_GET['val']));",
            },
            "java": {
                "vulnerable": "response.setHeader(\"X-Custom\", input);",
                "fixed": "response.setHeader(\"X-Custom\", input.replaceAll(\"[\\r\\n]\", \"\"));",
            },
            "csharp": {
                "vulnerable": "Response.Headers[\"X-Custom\"] = input;",
                "fixed": "Response.Headers[\"X-Custom\"] = Regex.Replace(input, @\"[\\r\\n]\", \"\");",
            },
            "go": {
                "vulnerable": "w.Header().Set(\"X-Custom\", input)",
                "fixed": "w.Header().Set(\"X-Custom\", strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(input))",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%0[da]|\\r|\\n)\" \"id:1144,phase:2,deny,status:403,log,msg:'Header Injection Response Splitting Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/113.html",
        ],
    },

    "log_injection_log_injection_via_format_string": {
        "title": "Log Injection via Format String",
        "description": (
            "Attacker injects format string specifiers (%s, %x, %n) into "
            "log statements to cause crashes or memory corruption."
        ),
        "remediation": (
            "Use parameterized logging (printf-style format strings with placeholders). "
            "Never concatenate user input into format strings."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "logging.info(f'User: {user_input}')",
                "fixed": "logging.info('User: %s', user_input)",
            },
            "javascript": {
                "vulnerable": "logger.info(`User: ${userInput}`);",
                "fixed": "logger.info('User: %s', userInput);",
            },
            "php": {
                "vulnerable": "error_log(sprintf('User: ' . $_GET['user']));",
                "fixed": "error_log('User: %s', 0, $_GET['user']);",
            },
            "java": {
                "vulnerable": "logger.info(\"User: \" + input);",
                "fixed": "logger.info(\"User: {}\", input);",
            },
            "csharp": {
                "vulnerable": "logger.LogInformation($\"User: {input}\");",
                "fixed": "logger.LogInformation(\"User: {User}\", input);",
            },
            "go": {
                "vulnerable": "log.Printf(\"User: \" + input)",
                "fixed": "log.Printf(\"User: %s\", input)",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx (%[sxdXofgpnc]|\\$\\{\\{.*\\}\\})\" \"id:1145,phase:2,deny,status:403,log,msg:'Format String Log Injection Detected'\"",
            ],
        },
        "references": [
            "https://cwe.mitre.org/data/definitions/134.html",
        ],
    },

    # ─── HTML INJECTION ──────────────────────────────────────────────────────

    "htmli_bare_tag": {
        "title": "HTML Injection - Bare Tag",
        "description": (
            "User-supplied input is reflected into the HTML document without proper "
            "encoding, allowing attackers to inject arbitrary HTML tags. This enables "
            "content spoofing, phishing form injection, page layout disruption, and "
            "in some cases escalation to XSS."
        ),
        "remediation": (
            "HTML-encode all user-supplied data before inserting it into HTML contexts. "
            "Use context-aware output encoding (e.g., htmlspecialchars() in PHP, "
            "html.escape() in Python). Apply a strict Content-Security-Policy. "
            "Never insert raw user input into innerHTML or document.write()."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "return f'<p>Hello {user_input}</p>'",
                "fixed": "import html; return f'<p>Hello {html.escape(user_input)}</p>'",
            },
            "php": {
                "vulnerable": "echo '<p>Hello ' . $_GET['name'] . '</p>';",
                "fixed": "echo '<p>Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</p>';",
            },
            "javascript": {
                "vulnerable": "element.innerHTML = userInput;",
                "fixed": "element.textContent = userInput; // use textContent, not innerHTML",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx <[a-zA-Z][^>]*>\" \"id:9001,phase:2,deny,status:403,log,msg:'HTML Injection Detected'\"",
            ],
        },
        "references": [
            "https://owasp.org/www-community/attacks/HTML_Injection",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    "htmli_phishing_form": {
        "title": "HTML Injection - Phishing Form",
        "description": (
            "Attacker injects a complete HTML <form> element, enabling them to create "
            "a fake login or data-capture form that submits to an attacker-controlled server. "
            "Victims interacting with the page may unknowingly submit credentials."
        ),
        "remediation": (
            "Apply strict HTML output encoding on all reflected content. "
            "Implement Content-Security-Policy with form-action directive to restrict "
            "where forms can submit data. Validate and reject inputs containing HTML tags."
        ),
        "code_examples": {},
        "waf_rules": {},
        "references": [
            "https://owasp.org/www-community/attacks/HTML_Injection",
        ],
    },

    # ─── TEXT INJECTION ──────────────────────────────────────────────────────

    "texti_crlf_text": {
        "title": "Text Injection - CRLF",
        "description": (
            "User input containing carriage return (\\r) and line feed (\\n) characters "
            "is reflected in the HTTP response, allowing attackers to inject arbitrary "
            "HTTP response headers or manipulate the response body. This can lead to "
            "HTTP response splitting, cache poisoning, session fixation, and XSS."
        ),
        "remediation": (
            "Strip or reject \\r and \\n characters from all user input before using it "
            "in HTTP headers or response bodies. Use a framework that automatically "
            "encodes header values. Validate input with allowlists."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "response.headers['Location'] = user_input",
                "fixed": "safe = user_input.replace('\\r', '').replace('\\n', ''); response.headers['Location'] = safe",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx [\\r\\n]\" \"id:9002,phase:2,deny,status:403,log,msg:'CRLF Injection Detected'\"",
            ],
        },
        "references": [
            "https://owasp.org/www-community/attacks/CRLF_Injection",
            "https://cwe.mitre.org/data/definitions/74.html",
        ],
    },

    "texti_content_spoof": {
        "title": "Text Injection - Content Spoofing",
        "description": (
            "User-supplied text is displayed on the page without sufficient context "
            "separation, enabling attackers to spoof official-looking messages, fake "
            "error pages, or social engineering content targeting other users."
        ),
        "remediation": (
            "Use output encoding appropriate for the context. Clearly separate user-generated "
            "content from application content with visual and structural boundaries. "
            "Apply Content-Security-Policy. Validate and sanitize all reflected input."
        ),
        "code_examples": {},
        "waf_rules": {},
        "references": [
            "https://portswigger.net/kb/issues/00200328_text-injection",
            "https://cwe.mitre.org/data/definitions/74.html",
        ],
    },

    # ─── LDAP INJECTION ──────────────────────────────────────────────────────

    "ldapi_auth_bypass": {
        "title": "LDAP Injection - Authentication Bypass",
        "description": (
            "User-supplied input is incorporated into LDAP filter queries without "
            "sanitization, allowing attackers to manipulate the filter logic. This can "
            "result in authentication bypass, account enumeration, and unauthorized "
            "access to directory service data."
        ),
        "remediation": (
            "Use parameterized LDAP queries or an LDAP library with built-in escaping. "
            "Escape all special LDAP characters: *, (, ), \\, NUL. "
            "Validate input against a strict allowlist before using in LDAP filters. "
            "Apply principle of least privilege to the LDAP service account."
        ),
        "code_examples": {
            "python": {
                "vulnerable": "ldap_filter = f'(uid={username})'",
                "fixed": "from ldap3.utils.conv import escape_filter_chars; ldap_filter = f'(uid={escape_filter_chars(username)})'",
            },
            "java": {
                "vulnerable": "String filter = \"(uid=\" + username + \")\"",
                "fixed": "String filter = \"(uid=\" + LdapEncoder.filterEncode(username) + \")\"",
            },
        },
        "waf_rules": {
            "modsecurity": [
                "SecRule ARGS \"@rx [\\*\\(\\)\\\\\\x00]\" \"id:9003,phase:2,deny,status:403,log,msg:'LDAP Injection Detected'\"",
            ],
        },
        "references": [
            "https://owasp.org/www-community/attacks/LDAP_Injection",
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
    },

    "ldapi_filter_bypass": {
        "title": "LDAP Injection - Filter Bypass",
        "description": (
            "Attacker manipulates LDAP filter expressions to enumerate directory entries, "
            "bypass access controls, or extract sensitive attributes."
        ),
        "remediation": (
            "Escape all LDAP filter meta-characters in user input. "
            "Use allow-listed values for LDAP attribute names. "
            "Monitor LDAP query logs for anomalous patterns."
        ),
        "code_examples": {},
        "waf_rules": {},
        "references": [
            "https://owasp.org/www-community/attacks/LDAP_Injection",
        ],
    },
}


class MitigationDB:
    """Class wrapper so callers can instantiate and call lookup helpers."""

    def get_mitigation(self, sub_type: str) -> Dict[str, Any]:
        return get_mitigation(sub_type)

    def get_cwe(self, family: str) -> str:
        return get_cwe(family)

    def get_all_sub_types(self) -> List[str]:
        return get_all_sub_types()

    def get_mitigations_for_family(self, family_key: str) -> List[Dict[str, Any]]:
        return get_mitigations_for_family(family_key)


def get_mitigation(sub_type: str) -> Dict[str, Any]:
    """Look up mitigation data for a specific injection sub-type key."""
    if sub_type in MITIGATION_DB:
        return MITIGATION_DB[sub_type]
    return {
        "title": "Unknown Injection Type",
        "description": "No mitigation data available for this sub-type.",
        "remediation": "Consult OWASP guidelines for general injection prevention.",
        "code_examples": {},
        "waf_rules": {},
        "references": ["https://owasp.org/www-community/attacks/"],
    }


def get_cwe(family: str) -> str:
    """Return the primary CWE ID for an injection family."""
    CWE_MAP = {
        "sqli": "CWE-89",
        "nosql": "CWE-943",
        "xss": "CWE-79",
        "cmdi": "CWE-78",
        "ssti": "CWE-1336",
        "xxe": "CWE-611",
        "ssrf": "CWE-918",
        "path_traversal": "CWE-22",
        "open_redirect": "CWE-601",
        "crlf": "CWE-93",
        "header_injection": "CWE-113",
        "email_injection": "CWE-94",
        "code_injection": "CWE-94",
        "formula_injection": "CWE-1236",
        "xpath": "CWE-91",
        "htmli": "CWE-79",
        "texti": "CWE-74",
        "ldapi": "CWE-90",
    }
    return CWE_MAP.get(family, "CWE-0")


def get_all_sub_types() -> List[str]:
    """Return all available injection sub-type keys."""
    return list(MITIGATION_DB.keys())


def get_mitigations_for_family(family_key: str) -> List[Dict[str, Any]]:
    """Return all mitigations whose key starts with a given prefix."""
    return [
        {"key": k, **v}
        for k, v in MITIGATION_DB.items()
        if k.startswith(family_key)
    ]


def build_mitigation_section(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build a mitigation section from a list of findings.

    Each finding should have 'injection_family' and 'injection_subtype' fields.
    Returns deduplicated mitigation entries.
    """
    seen = set()
    sections = []
    for finding in findings:
        sub_type = finding.get("injection_subtype", "")
        if sub_type and sub_type not in seen:
            seen.add(sub_type)
            mitigation = get_mitigation(sub_type)
            if mitigation["title"] != "Unknown Injection Type":
                sections.append({
                    "finding_title": finding.get("title", ""),
                    "sub_type": sub_type,
                    **mitigation,
                })
    return sections
