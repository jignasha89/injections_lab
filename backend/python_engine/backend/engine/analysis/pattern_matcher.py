import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class PatternMatcher:
    def __init__(self):
        self.sql_patterns = self._build_sql_patterns()
        self.command_patterns = self._build_command_patterns()
        self.xss_patterns = self._build_xss_patterns()
        self.ssti_patterns = self._build_ssti_patterns()
        self.xxe_patterns = self._build_xxe_patterns()
        self.ssrf_patterns = self._build_ssrf_patterns()
        self.error_stack_patterns = self._build_error_stack_patterns()
        self.oob_patterns = self._build_oob_patterns()
        self.lfi_patterns = self._build_lfi_patterns()
        self.generic_patterns = self._build_generic_patterns()

    def _build_sql_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"ORA-\d{5}", "oracle_error", "definite"),
            (r"ORA-\d{4,5}:\s*[^\"'\s]+", "oracle_error_msg", "definite"),
            (r"SQLSTATE\[[A-Z0-9]{5}\]", "pdo_sqlstate", "definite"),
            (r"SQLSTATE:\s*[A-Z0-9]{5}", "pdo_sqlstate_alt", "definite"),
            (r"mysql_fetch", "mysql_fetch", "definite"),
            (r"mysql_num_rows", "mysql_num_rows", "definite"),
            (r"mysql_query", "mysql_query", "definite"),
            (r"MySQLSyntaxErrorException", "mysql_syntax", "definite"),
            (r"You have an error in your SQL syntax", "mysql_syntax_msg", "definite"),
            (r"Warning.*mysql_", "mysql_warning", "definite"),
            (r"MySQL server version for the right syntax", "mysql_version_leak", "definite"),
            (r"sqlite3\.", "sqlite3_module", "definite"),
            (r"SQLITE_ERROR", "sqlite_error", "definite"),
            (r"near \"[^\"]+\": syntax error", "sqlite_syntax", "definite"),
            (r"SQLite\.Driver", "sqlite_driver", "definite"),
            (r"unrecognized token:", "sqlite_token", "probable"),
            (r"PostgreSQL.*ERROR", "postgresql_error", "definite"),
            (r"pg_query\(\)", "pg_query", "definite"),
            (r"pg_exec\(\)", "pg_exec", "definite"),
            (r"PSQLException", "psql_exception", "definite"),
            (r"ERROR:\s+syntax error at or near", "pg_syntax", "definite"),
            (r"org\.postgresql\.util\.PSQLException", "pg_exception_class", "definite"),
            (r"Server error.*PostgreSQL", "pg_server_error", "probable"),
            (r"Microsoft.*ODBC.*SQL Server", "mssql_odbc", "definite"),
            (r"Unclosed quotation mark after the character string", "mssql_unclosed_quote", "definite"),
            (r"Conversion failed when converting", "mssql_conversion", "definite"),
            (r"Line \d+: Incorrect syntax near", "mssql_syntax", "definite"),
            (r"SqlException", "generic_sql_exception", "definite"),
            (r"System\.Data\.SqlClient\.SqlException", "dotnet_sql_exception", "definite"),
            (r"com\.mysql\.jdbc\.exceptions\.JDBC", "jdbc_mysql", "definite"),
            (r"java\.sql\.SQLException", "java_sql_exception", "definite"),
            (r"JDBCException", "jdbc_exception", "probable"),
            (r"Transaction count after EXECUTE indicates", "mssql_transaction", "definite"),
            (r"Invalid column name", "invalid_column", "definite"),
            (r"Invalid object name", "invalid_object", "probable"),
            (r"Column name mismatch", "column_mismatch", "probable"),
            (r"Table.*doesn't exist", "table_not_exist", "probable"),
            (r"Unknown column", "unknown_column", "definite"),
            (r"subquery returns more than 1 row", "subquery_multiple", "definite"),
            (r"Duplicate entry", "duplicate_entry", "probable"),
            (r"Data truncation", "data_truncation", "probable"),
            (r"Column count doesn't match", "column_count_mismatch", "definite"),
            (r"INSERT command denied to user", "insert_denied", "definite"),
            (r"SELECT command denied to user", "select_denied", "definite"),
            (r"Access denied for user", "access_denied_mysql", "probable"),
            (r"quoted string not properly terminated", "unterminated_string", "definite"),
            (r"ORA-01756", "oracle_quoted_string", "definite"),
            (r"not well-formed", "xml_malformed_sql", "probable"),
            (r"XPath syntax error", "xpath_error", "probable"),
            (r"XQuery syntax error", "xquery_error", "probable"),
            (r"String or binary data would be truncated", "data_truncation_mssql", "definite"),
            (r"Arithmetic overflow error", "arithmetic_overflow", "definite"),
            (r"The conversion of a.*data type.*failed", "type_conversion_fail", "definite"),
            (r"Must declare the scalar variable", "undeclared_variable", "definite"),
            (r"Invalid use of NULL", "null_usage", "probable"),
            (r"Division by zero", "division_zero", "probable"),
            (r"The SELECT permission was denied", "permission_denied", "definite"),
            (r"Could not find stored procedure", "stored_proc_missing", "probable"),
            (r"Syntax error near.*line", "syntax_error_generic", "probable"),
            (r"Unexpected end of command", "unexpected_eoc", "probable"),
            (r"Invalid column reference", "invalid_column_ref", "probable"),
            (r"Cursor.*not found", "cursor_not_found", "probable"),
            (r"FOR XML.*directive", "for_xml", "probable"),
            (r"OPENROWSET", "openrowset", "probable"),
            (r"OPENQUERY", "openquery", "probable"),
            (r"BULK INSERT", "bulk_insert", "probable"),
            (r"xp_cmdshell", "xp_cmdshell", "definite"),
            (r"xp_dirtree", "xp_dirtree", "definite"),
            (r"xp_fileexist", "xp_fileexist", "definite"),
            (r"sp_OACreate", "sp_oacreate", "definite"),
            (r"sp_makewebtask", "sp_makewebtask", "definite"),
            (r"UNION SELECT", "union_select", "definite"),
            (r"UNION ALL SELECT", "union_all_select", "definite"),
            (r"ORDER BY \d+", "order_by_numeric", "probable"),
            (r"HAVING 1=1", "having_clause", "probable"),
            (r"GROUP BY.*HAVING", "group_by_having", "probable"),
            (r"WAITFOR DELAY", "waitfor_delay", "definite"),
            (r"BENCHMARK\(", "benchmark_sleep", "definite"),
            (r"SLEEP\(", "sleep_function", "definite"),
            (r"pg_sleep\(", "pg_sleep", "definite"),
            (r"DBMS_PIPE\.RECEIVE_MESSAGE", "dbms_pipe", "definite"),
            (r"LOAD_FILE\(", "load_file", "definite"),
            (r"INTO OUTFILE", "into_outfile", "definite"),
            (r"INTO DUMPFILE", "into_dumpfile", "definite"),
            (r"INFORMATION_SCHEMA", "info_schema", "probable"),
            (r"sys\.columns", "sys_columns", "probable"),
            (r"sys\.objects", "sys_objects", "probable"),
            (r"sys\.tables", "sys_tables", "probable"),
            (r"pg_catalog", "pg_catalog", "probable"),
            (r"pg_tables", "pg_tables", "probable"),
            (r"SHOW TABLES", "show_tables", "probable"),
            (r"SHOW DATABASES", "show_databases", "probable"),
            (r"SHOW COLUMNS", "show_columns", "probable"),
            (r"DESCRIBE\s+\w+", "describe_table", "probable"),
            (r"CONCAT\(", "concat_function", "probable"),
            (r"CHAR\(", "char_function", "probable"),
            (r"CONVERT\(", "convert_function", "probable"),
            (r"CAST\(", "cast_function", "probable"),
            (r"ASCII\(", "ascii_function", "probable"),
            (r"SUBSTRING\(", "substring_function", "probable"),
            (r"SUBSTR\(", "substr_function", "probable"),
            (r"LENGTH\(", "length_function_sql", "probable"),
            (r"UPDATE.*SET", "update_set", "probable"),
            (r"DELETE FROM", "delete_from", "probable"),
            (r"DROP TABLE", "drop_table", "probable"),
            (r"DROP DATABASE", "drop_database", "probable"),
            (r"TRUNCATE TABLE", "truncate_table", "probable"),
            (r"ALTER TABLE", "alter_table", "probable"),
            (r"CREATE TABLE", "create_table", "probable"),
            (r"GRANT.*ON", "grant_permission", "probable"),
            (r"REVOKE.*ON", "revoke_permission", "probable"),
            (r"EXEC\(", "exec_function", "probable"),
            (r"EXECUTE\(", "execute_function", "probable"),
            (r"EXECUTE IMMEDIATE", "execute_immediate", "probable"),
            (r"DBMS_UTILITY", "dbms_utility", "probable"),
            (r"UTL_HTTP", "utl_http", "probable"),
            (r"UTL_FILE", "utl_file", "probable"),
            (r"CTXSYS", "ctxsys", "probable"),
            (r"DBMS_SCHEDULER", "dbms_scheduler", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_command_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"root:x:0:0", "passwd_root", "definite"),
            (r"uid=\d+\(?\w*\)?\s+gid=\d+", "id_command", "definite"),
            (r"/bin/bash", "bash_ref", "probable"),
            (r"/bin/sh", "sh_ref", "probable"),
            (r"/bin/zsh", "zsh_ref", "probable"),
            (r"System32", "windows_system32", "definite"),
            (r"Windows\\System32", "windows_system32_path", "definite"),
            (r"C:\\Windows", "c_windows", "definite"),
            (r"/etc/passwd", "etc_passwd", "definite"),
            (r"/etc/shadow", "etc_shadow", "definite"),
            (r"/etc/hosts", "etc_hosts", "probable"),
            (r"whoami", "whoami_output", "definite"),
            (r"hostname", "hostname_output", "probable"),
            (r"net user", "net_user", "definite"),
            (r"net group", "net_group", "definite"),
            (r"ifconfig", "ifconfig_output", "probable"),
            (r"ip addr", "ip_addr", "probable"),
            (r"ls -la", "ls_la", "probable"),
            (r"dir ", "dir_command", "probable"),
            (r"type\s+", "type_command", "probable"),
            (r"cat\s+/etc", "cat_etc", "definite"),
            (r"more\s+/etc", "more_etc", "definite"),
            (r"less\s+/etc", "less_etc", "probable"),
            (r"head\s+/etc", "head_etc", "probable"),
            (r"tail\s+/etc", "tail_etc", "probable"),
            (r"wget\s+", "wget_command", "probable"),
            (r"curl\s+", "curl_command", "probable"),
            (r"ping\s+", "ping_output", "probable"),
            (r"nslookup", "nslookup_output", "probable"),
            (r"dig\s+", "dig_output", "probable"),
            (r"python\s+-c", "python_command", "definite"),
            (r"python3\s+-c", "python3_command", "definite"),
            (r"perl\s+-e", "perl_command", "definite"),
            (r"ruby\s+-e", "ruby_command", "definite"),
            (r"php\s+-r", "php_command", "definite"),
            (r"bash\s+-c", "bash_command", "definite"),
            (r"sh\s+-c", "sh_command", "definite"),
            (r"eval\s*\(", "eval_execution", "definite"),
            (r"exec\s*\(", "exec_execution", "definite"),
            (r"system\s*\(", "system_execution", "definite"),
            (r"passthru\s*\(", "passthru_execution", "definite"),
            (r"shell_exec\s*\(", "shell_exec_execution", "definite"),
            (r"popen\s*\(", "popen_execution", "definite"),
            (r"proc_open\s*\(", "proc_open_execution", "definite"),
            (r"Runtime\.getRuntime\(\)\.exec", "java_runtime_exec", "definite"),
            (r"ProcessBuilder", "java_process_builder", "probable"),
            (r"subprocess\.call", "python_subprocess", "definite"),
            (r"os\.system", "python_os_system", "definite"),
            (r"os\.popen", "python_os_popen", "definite"),
            (r"Command\.New-Object", "powershell_new_object", "probable"),
            (r"Invoke-Expression", "powershell_invoke_expression", "definite"),
            (r"IEX\s*\(", "powershell_iex", "definite"),
            (r"Start-Process", "powershell_start_process", "probable"),
            (r"Get-Content", "powershell_get_content", "probable"),
            (r"Set-Content", "powershell_set_content", "probable"),
            (r"DownloadString", "dotnet_download_string", "definite"),
            (r"DownloadFile", "dotnet_download_file", "definite"),
            (r"Invoke-WebRequest", "powershell_web_request", "probable"),
            (r"Invoke-RestMethod", "powershell_rest_method", "probable"),
            (r"bitsadmin", "bitsadmin", "probable"),
            (r"certutil", "certutil", "probable"),
            (r"mshta", "mshta", "probable"),
            (r"wscript", "wscript", "probable"),
            (r"cscript", "cscript", "probable"),
            (r"regsvr32", "regsvr32", "probable"),
            (r"rundll32", "rundll32", "probable"),
            (r"tasklist", "tasklist_output", "probable"),
            (r"taskkill", "taskkill_command", "probable"),
            (r"sc query", "sc_query", "probable"),
            (r"reg query", "reg_query", "probable"),
            (r"wmic", "wmic_output", "probable"),
            (r"systeminfo", "systeminfo_output", "probable"),
            (r"ipconfig", "ipconfig_output", "probable"),
            (r"Get-Process", "powershell_get_process", "probable"),
            (r"Get-Service", "powershell_get_service", "probable"),
            (r"Get-WmiObject", "powershell_get_wmi", "probable"),
            (r"Select-String", "powershell_select_string", "probable"),
            (r"Findstr", "findstr_command", "probable"),
            (r"/bin/.*-c\s", "unix_exec_chain", "definite"),
            (r"&&\s*\w+", "command_chain", "probable"),
            (r"\|\s*\w+", "pipe_command", "probable"),
            (r";\s*\w+", "semicolon_command", "probable"),
            (r"`\w+`", "backtick_exec", "probable"),
            (r"\$\(\w+\)", "dollar_paren_exec", "probable"),
            (r"/dev/null", "dev_null", "probable"),
            (r"/proc/self", "proc_self", "probable"),
            (r"/dev/tcp", "dev_tcp", "definite"),
            (r"mkfifo", "mkfifo", "probable"),
            (r"nc\s+-", "netcat", "probable"),
            (r"ncat", "ncat", "probable"),
            (r"socat", "socat", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_xss_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"<script[^>]*>", "script_tag", "probable"),
            (r"javascript:", "javascript_uri", "probable"),
            (r"onerror\s*=", "onerror_handler", "probable"),
            (r"onload\s*=", "onload_handler", "probable"),
            (r"onclick\s*=", "onclick_handler", "probable"),
            (r"onmouseover\s*=", "onmouseover_handler", "probable"),
            (r"onfocus\s*=", "onfocus_handler", "probable"),
            (r"onblur\s*=", "onblur_handler", "probable"),
            (r"onsubmit\s*=", "onsubmit_handler", "probable"),
            (r"onchange\s*=", "onchange_handler", "probable"),
            (r"oninput\s*=", "oninput_handler", "probable"),
            (r"onkeydown\s*=", "onkeydown_handler", "probable"),
            (r"onkeyup\s*=", "onkeyup_handler", "probable"),
            (r"onkeypress\s*=", "onkeypress_handler", "probable"),
            (r"onmousedown\s*=", "onmousedown_handler", "probable"),
            (r"onmouseup\s*=", "onmouseup_handler", "probable"),
            (r"ondblclick\s*=", "ondblclick_handler", "probable"),
            (r"oncontextmenu\s*=", "oncontextmenu_handler", "probable"),
            (r"onreset\s*=", "onreset_handler", "probable"),
            (r"onselect\s*=", "onselect_handler", "probable"),
            (r"onabort\s*=", "onabort_handler", "probable"),
            (r"onbeforeunload\s*=", "onbeforeunload_handler", "probable"),
            (r"onhashchange\s*=", "onhashchange_handler", "probable"),
            (r"onpopstate\s*=", "onpopstate_handler", "probable"),
            (r"onstorage\s*=", "onstorage_handler", "probable"),
            (r"onanimationend\s*=", "onanimationend_handler", "probable"),
            (r"ontransitionend\s*=", "ontransitionend_handler", "probable"),
            (r"<iframe[^>]*src\s*=\s*[\"']?javascript:", "iframe_js", "definite"),
            (r"<img[^>]+src\s*=\s*[\"']?javascript:", "img_js", "definite"),
            (r"<svg[^>]+onload\s*=", "svg_onload", "definite"),
            (r"<body[^>]+onload\s*=", "body_onload", "definite"),
            (r"<input[^>]+onfocus\s*=", "input_onfocus", "definite"),
            (r"<marquee[^>]+onstart\s*=", "marquee_onstart", "definite"),
            (r"<video[^>]+onerror\s*=", "video_onerror", "definite"),
            (r"<audio[^>]+onerror\s*=", "audio_onerror", "definite"),
            (r"<details[^>]+ontoggle\s*=", "details_ontoggle", "definite"),
            (r"<a[^>]+href\s*=\s*[\"']?javascript:", "anchor_js", "definite"),
            (r"document\.cookie", "document_cookie", "definite"),
            (r"document\.write\s*\(", "document_write", "definite"),
            (r"window\.location", "window_location", "probable"),
            (r"eval\s*\(", "eval_xss", "definite"),
            (r"String\.fromCharCode", "from_char_code", "probable"),
            (r"atob\s*\(", "atob_decode", "probable"),
            (r"alert\s*\(", "alert_function", "probable"),
            (r"confirm\s*\(", "confirm_function", "probable"),
            (r"prompt\s*\(", "prompt_function", "probable"),
            (r"document\.domain", "document_domain", "probable"),
            (r"document\.referrer", "document_referrer", "probable"),
            (r"document\.URL", "document_url", "probable"),
            (r"window\.name", "window_name", "probable"),
            (r"localStorage", "local_storage", "probable"),
            (r"sessionStorage", "session_storage", "probable"),
            (r"XMLHttpRequest", "xhr_xss", "probable"),
            (r"fetch\s*\(", "fetch_xss", "probable"),
            (r"<base[^>]+href\s*=", "base_href", "probable"),
            (r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", "meta_refresh", "probable"),
            (r"expression\s*\(", "css_expression", "definite"),
            (r"-moz-binding", "moz_binding", "definite"),
            (r"url\s*\(\s*[\"']?javascript:", "css_js_url", "definite"),
            (r"<object[^>]+data\s*=", "object_data", "probable"),
            (r"<embed[^>]+src\s*=", "embed_src", "probable"),
            (r"<applet[^>]+code\s*=", "applet_code", "probable"),
            (r"formaction\s*=", "formaction", "probable"),
            (r"<form[^>]+action\s*=\s*[\"']?javascript:", "form_js_action", "definite"),
            (r"data:text/html", "data_uri_html", "definite"),
            (r"<xmp>", "xmp_tag", "probable"),
            (r"<plaintext>", "plaintext_tag", "probable"),
            (r"<listing>", "listing_tag", "probable"),
            (r"<textarea[^>]+>", "textarea_xss", "probable"),
            (r"<title[^>]+>", "title_xss", "probable"),
            (r"<!--.*-->", "html_comment", "probable"),
            (r"<!\[CDATA\[", "cdata_section", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_ssti_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"\{\{.*\}\}", "double_curly", "probable"),
            (r"\{\%.*\%\}", "jinja_block", "probable"),
            (r"\{\{7\*7\}\}", "math_ssti", "definite"),
            (r"\{\{.*7\*7.*\}\}", "math_ssti_expr", "definite"),
            (r"\{\{.*config.*\}\}", "config_access", "definite"),
            (r"\{\{.*self.*\}\}", "self_access", "definite"),
            (r"\{\{.*request.*\}\}", "request_access", "definite"),
            (r"\{\{.*os.*\}\}", "os_access_ssti", "definite"),
            (r"\{\{.*import.*\}\}", "import_ssti", "definite"),
            (r"\{\{.*class.*\}\}", "class_access", "probable"),
            (r"\{\{.*mro.*\}\}", "mro_access", "definite"),
            (r"\{\{.*subclasses.*\}\}", "subclasses_access", "definite"),
            (r"\{\{.*globals.*\}\}", "globals_access", "definite"),
            (r"\{\{.*builtins.*\}\}", "builtins_access", "definite"),
            (r"\{\{.*__.*__.*\}\}", "dunder_access", "probable"),
            (r"\$\{.*\}", "dollar_curly", "probable"),
            (r"\$\{7\*7\}", "java_math_ssti", "definite"),
            (r"\$\{.*class.*\}", "java_class_access", "probable"),
            (r"<%=.*%>", "erb_tag", "probable"),
            (r"<%.*%>", "jsp_tag", "probable"),
            (r"\[\[.*\]\]", "double_bracket", "probable"),
            (r"\#{.*\}", "ruby_interpolation", "probable"),
            (r"<\?.*\?>", "php_tag", "probable"),
            (r"__import__\(", "import_call", "definite"),
            (r"__builtins__", "builtins_ref", "definite"),
            (r"\.os\.", "os_module", "definite"),
            (r"\.subprocess\.", "subprocess_module", "definite"),
            (r"\.popen\(", "popen_call", "definite"),
            (r"\.read\(\)", "read_call", "probable"),
            (r"\.write\(\)", "write_call", "probable"),
            (r"lipsum", "lipsum_ssti", "definite"),
            (r"cycler", "cycler_ssti", "definite"),
            (r"joiner", "joiner_ssti", "definite"),
            (r"namespace", "namespace_ssti", "probable"),
            (r"\{\{.*\|.*\}\}", "jinja_filter", "probable"),
            (r"\{\{.*range.*\}\}", "jinja_range", "probable"),
            (r"\{\{.*dict.*\}\}", "jinja_dict", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_xxe_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"ENTITY\s+\w+\s+SYSTEM", "xxe_entity_system", "definite"),
            (r"ENTITY\s+\w+\s+PUBLIC", "xxe_entity_public", "definite"),
            (r"<!DOCTYPE[^>]+\[", "dtd_internal_subset", "definite"),
            (r"SYSTEM\s+[\"'][^\"']+[\"']", "system_identifier", "probable"),
            (r"PUBLIC\s+[\"'][^\"']+[\"']", "public_identifier", "probable"),
            (r"file:///etc/passwd", "file_protocol_passwd", "definite"),
            (r"file:///c/", "file_protocol_windows", "definite"),
            (r"expect://", "expect_protocol", "definite"),
            (r"php://filter", "php_filter", "definite"),
            (r"php://input", "php_input", "definite"),
            (r"data://", "data_protocol", "probable"),
            (r"xxe", "xxe_keyword", "probable"),
            (r"DTD\s+", "dtd_keyword", "probable"),
            (r"DOCTYPE\s+\w+", "doctype_keyword", "probable"),
            (r"element\s+<!ENTITY", "entity_declaration", "definite"),
            (r"parsedEntity", "parsed_entity", "probable"),
            (r"externalEntity", "external_entity", "probable"),
            (r"ParameterEntity", "parameter_entity", "definite"),
            (r"<!ELEMENT", "dtd_element", "probable"),
            (r"<!ATTLIST", "dtd_attlist", "probable"),
            (r"<!NOTATION", "dtd_notation", "probable"),
            (r"<\?xml\s+version", "xml_declaration", "probable"),
            (r"ENCODING\s*=\s*[\"']", "encoding_decl", "probable"),
            (r"StAX", "stax_parser", "probable"),
            (r"DocumentBuilderFactory", "jaxp_factory", "probable"),
            (r"XMLReader", "xml_reader", "probable"),
            (r"SAXParser", "sax_parser", "probable"),
            (r"TransformerFactory", "transformer_factory", "probable"),
            (r"SchemaFactory", "schema_factory", "probable"),
            (r"VALIDATION", "validation_mode", "probable"),
            (r"DISALLOW-DOCTYPE-DECL", "disallow_dtd", "probable"),
            (r"external-general-entities", "external_gen_entities", "probable"),
            (r"external-parameter-entities", "external_param_entities", "probable"),
            (r"Internal entity:", "internal_entity_leak", "definite"),
            (r"External entity:", "external_entity_leak", "definite"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_ssrf_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"169\.254\.169\.254", "aws_metadata", "definite"),
            (r"metadata\.google\.internal", "gcp_metadata", "definite"),
            (r"169\.254\.169\.254/latest/meta-data/", "aws_metadata_path", "definite"),
            (r"169\.254\.169\.254/latest/user-data/", "aws_user_data", "definite"),
            (r"169\.254\.169\.254/latest/dynamic/", "aws_dynamic", "definite"),
            (r"fd00:ec2::254", "aws_ipv6_metadata", "definite"),
            (r"100\.100\.100\.200", "aliyun_metadata", "definite"),
            (r"169\.254\.169\.254/metadata", "azure_metadata", "definite"),
            (r"metadata\.azure\.com", "azure_metadata_host", "definite"),
            (r"instance-data/latest", "gcp_instance_data", "definite"),
            (r"http://\[::1\]", "ipv6_localhost", "probable"),
            (r"http://127\.0\.0\.1", "localhost_127", "probable"),
            (r"http://localhost", "localhost_name", "probable"),
            (r"http://\[0:0:0:0\]", "ipv6_zero", "probable"),
            (r"http://0x7f000001", "hex_localhost", "definite"),
            (r"http://017700000001", "octal_localhost", "definite"),
            (r"http://2130706433", "decimal_localhost", "definite"),
            (r"http://127\.1", "short_localhost", "definite"),
            (r"http://127\.0\.1", "alt_localhost", "probable"),
            (r"amznaws", "aws_url", "probable"),
            (r"amazonaws\.com", "aws_domain", "probable"),
            (r"googleapis\.com", "gcp_apis", "probable"),
            (r"azure\.com", "azure_domain", "probable"),
            (r"cloudflare\.com", "cloudflare_domain", "probable"),
            (r"Could not resolve host", "dns_resolution_fail", "probable"),
            (r"Connection refused", "connection_refused", "probable"),
            (r"Connection timed out", "connection_timeout", "probable"),
            (r"Network is unreachable", "network_unreachable", "probable"),
            (r"No route to host", "no_route_to_host", "probable"),
            (r"Name or service not known", "dns_not_known", "probable"),
            (r"getaddrinfo failed", "getaddrinfo_fail", "probable"),
            (r"Failed to connect", "connect_fail", "probable"),
            (r"SSL.*certificate", "ssl_cert_error", "probable"),
            (r" certificate verify failed", "cert_verify_fail", "probable"),
            (r"Too many redirects", "too_many_redirects", "probable"),
            (r"Redirect.*location", "redirect_location", "probable"),
            (r"Server:.*\d+\.\d+\.\d+", "server_version_leak", "probable"),
            (r"X-Powered-By", "powered_by_leak", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_error_stack_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"Traceback \(most recent call last\)", "python_traceback", "definite"),
            (r"File \"[^\"]+\",\s*line\s+\d+", "python_file_line", "definite"),
            (r"SyntaxError:", "python_syntax_error", "definite"),
            (r"NameError:", "python_name_error", "definite"),
            (r"TypeError:", "python_type_error", "probable"),
            (r"ValueError:", "python_value_error", "probable"),
            (r"KeyError:", "python_key_error", "probable"),
            (r"IndexError:", "python_index_error", "probable"),
            (r"AttributeError:", "python_attr_error", "probable"),
            (r"ImportError:", "python_import_error", "probable"),
            (r"ModuleNotFoundError:", "python_module_not_found", "probable"),
            (r"RuntimeError:", "python_runtime_error", "probable"),
            (r"IOError:", "python_io_error", "probable"),
            (r"OSError:", "python_os_error", "probable"),
            (r"java\.lang\.\w+Exception", "java_exception", "definite"),
            (r"java\.lang\.\w+Error", "java_error", "definite"),
            (r"at\s+[\w.]+\([\w.]+:\d+\)", "java_stack_frame", "definite"),
            (r"Caused by:", "java_caused_by", "definite"),
            (r"Exception in thread", "java_thread_exception", "definite"),
            (r"NullPointer", "java_null_pointer", "probable"),
            (r"ClassCast", "java_class_cast", "probable"),
            (r"IllegalArgument", "java_illegal_arg", "probable"),
            (r"IndexOutOf", "java_index_out", "probable"),
            (r"StackOverflow", "java_stack_overflow", "probable"),
            (r"OutOfMemory", "java_out_of_memory", "probable"),
            (r"at\s+#\d+:", "go_stack_frame", "probable"),
            (r"goroutine\s+\d+\s+\[", "go_goroutine", "definite"),
            (r"panic:", "go_panic", "definite"),
            (r"fatal error:", "go_fatal", "definite"),
            (r"runtime\.error", "go_runtime_error", "probable"),
            (r"PHP (Fatal|Parse|Notice|Warning|Deprecated) error", "php_error", "definite"),
            (r"in\s+[^\s]+\.php\s+on line\s+\d+", "php_error_location", "definite"),
            (r"Uncaught\s+\w+Exception:", "php_uncaught", "definite"),
            (r"Stack trace:", "stack_trace", "probable"),
            (r"Call stack:", "call_stack", "probable"),
            (r"Debug backtrace:", "debug_backtrace", "probable"),
            (r"at\s+\w+\.\w+\(", "generic_stack_frame", "probable"),
            (r"line\s+\d+\s+in\s+", "line_in_file", "probable"),
            (r"\w+Exception:\s*.*", "generic_exception_msg", "probable"),
            (r"\w+Error:\s*.*", "generic_error_msg", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE | re.MULTILINE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_oob_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"oob-?dns", "oob_dns", "definite"),
            (r"interact\.sh", "interactsh", "definite"),
            (r"burpcollaborator", "burp_collaborator", "definite"),
            (r"canarytokens", "canarytokens", "definite"),
            (r"requestbin", "requestbin", "probable"),
            (r"webhook\.site", "webhook_site", "probable"),
            (r"hookbin", "hookbin", "probable"),
            (r"interact\.sh", "interactsh_domain", "definite"),
            (r"\w+\.oast\.fun", "oast_fun", "definite"),
            (r"\w+\.oast\.live", "oast_live", "definite"),
            (r"\w+\.oast\.pro", "oast_pro", "definite"),
            (r"\w+\.oast\.me", "oast_me", "definite"),
            (r"\w+\.burpcollaborator\.net", "burp_net", "definite"),
            (r"\w+\.interact\.sh", "interact_sh", "definite"),
            (r"DNS:", "dns_exfil_header", "probable"),
            (r"HTTP:", "http_exfil_header", "probable"),
            (r"Received:\s*.*\bfrom\b", "email_received", "probable"),
            (r"X-Original-URL", "original_url_header", "probable"),
            (r"X-Rewrite-URL", "rewrite_url_header", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_lfi_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"root:x:0:0", "passwd_content", "definite"),
            (r"\[boot loader\]", "boot_ini_content", "definite"),
            (r"\[operating systems\]", "boot_ini_os", "definite"),
            (r"Windows NT", "windows_nt_content", "probable"),
            (r"Windows XP", "windows_xp_content", "probable"),
            (r"localhost:127\.0\.0\.1", "hosts_file_content", "definite"),
            (r"::1\s+localhost", "hosts_file_ipv6", "definite"),
            (r"# This file", "hosts_file_comment", "probable"),
            (r"127\.0\.0\.1\s+localhost", "hosts_entry", "probable"),
            (r"127\.0\.0\.1\s+\w+", "hosts_custom_entry", "probable"),
            (r"<\?php", "php_source_leak", "definite"),
            (r"mysql_connect", "php_mysql_connect", "definite"),
            (r"mysqli_connect", "php_mysqli_connect", "definite"),
            (r"PDO\(", "php_pdo_construct", "definite"),
            (r"password", "password_keyword", "probable"),
            (r"db_pass", "db_password_key", "probable"),
            (r"DB_PASSWORD", "env_db_password", "definite"),
            (r"DB_HOST", "env_db_host", "probable"),
            (r"DB_USER", "env_db_user", "probable"),
            (r"SECRET_KEY", "env_secret_key", "definite"),
            (r"API_KEY", "env_api_key", "definite"),
            (r"AWS_ACCESS_KEY", "env_aws_key", "definite"),
            (r"AWS_SECRET", "env_aws_secret", "definite"),
            (r"-----BEGIN", "private_key_header", "definite"),
            (r"-----END.*PRIVATE KEY", "private_key_end", "definite"),
            (r"BEGIN CERTIFICATE", "certificate_header", "probable"),
            (r"ssh-rsa", "ssh_key", "definite"),
            (r"ssh-ed25519", "ssh_ed25519", "definite"),
            (r"AKIA[0-9A-Z]{16}", "aws_access_key_id", "definite"),
            (r"password\s*=\s*[\"'][^\"']+[\"']", "password_assign", "definite"),
            (r"passwd\s*=\s*[\"'][^\"']+[\"']", "passwd_assign", "definite"),
            (r"secret\s*=\s*[\"'][^\"']+[\"']", "secret_assign", "probable"),
            (r"token\s*=\s*[\"'][^\"']+[\"']", "token_assign", "probable"),
            (r"/proc/version", "proc_version", "definite"),
            (r"/proc/self/environ", "proc_self_environ", "definite"),
            (r"/proc/self/cmdline", "proc_self_cmdline", "definite"),
            (r"/proc/self/status", "proc_self_status", "probable"),
            (r"/proc/cpuinfo", "proc_cpuinfo", "probable"),
            (r"boot\.ini", "boot_ini_path", "definite"),
            (r"win\.ini", "win_ini_path", "definite"),
            (r"system\.ini", "system_ini_path", "probable"),
            (r"/var/log/", "var_log_path", "probable"),
            (r"/var/log/auth\.log", "auth_log", "definite"),
            (r"/var/log/apache2/", "apache_log", "probable"),
            (r"/var/log/nginx/", "nginx_log", "probable"),
            (r"/etc/apache2/", "apache_config", "probable"),
            (r"/etc/nginx/", "nginx_config", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _build_generic_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            (r"500 Internal Server Error", "internal_server_error", "probable"),
            (r"403 Forbidden", "forbidden", "probable"),
            (r"404 Not Found", "not_found", "probable"),
            (r"401 Unauthorized", "unauthorized", "probable"),
            (r"400 Bad Request", "bad_request", "probable"),
            (r"502 Bad Gateway", "bad_gateway", "probable"),
            (r"503 Service Unavailable", "service_unavailable", "probable"),
            (r"504 Gateway Timeout", "gateway_timeout", "probable"),
            (r"Debug mode is on", "debug_mode", "definite"),
            (r"Debugging mode", "debugging_mode", "probable"),
            (r"stack trace", "generic_stack_trace", "probable"),
            (r"error details", "error_details", "probable"),
            (r"internal error", "generic_internal_error", "probable"),
            (r"server error", "generic_server_error", "probable"),
            (r"application error", "application_error", "probable"),
            (r"An error occurred", "error_occurred", "probable"),
            (r"Something went wrong", "something_wrong", "probable"),
            (r"We encountered an error", "encountered_error", "probable"),
            (r"Error processing request", "process_error", "probable"),
            (r"Exception was thrown", "exception_thrown", "probable"),
            (r"Unhandled exception", "unhandled_exception", "probable"),
            (r"Runtime exception", "runtime_exception", "probable"),
            (r"Configuration error", "config_error", "probable"),
            (r"Database error", "database_error", "probable"),
            (r"Connection error", "connection_error", "probable"),
            (r"Permission denied", "permission_denied_generic", "probable"),
            (r"Access denied", "access_denied_generic", "probable"),
            (r"Not authorized", "not_authorized", "probable"),
            (r"Invalid request", "invalid_request", "probable"),
            (r"Malformed request", "malformed_request", "probable"),
            (r"Request too large", "request_too_large", "probable"),
            (r"Timeout", "timeout_generic", "probable"),
            (r"Rate limit", "rate_limit", "probable"),
            (r"Too many requests", "too_many_requests", "probable"),
        ]
        compiled = []
        for pattern, name, confidence in patterns:
            compiled.append(
                {
                    "regex": re.compile(pattern, re.IGNORECASE),
                    "name": name,
                    "confidence": confidence,
                }
            )
        return compiled

    def _match_patterns(
        self, text: str, patterns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        matches = []
        for pat in patterns:
            try:
                match = pat["regex"].search(text)
                if match:
                    matched_text = match.group(0)
                    matches.append(
                        {
                            "pattern_name": pat["name"],
                            "matched_text": matched_text,
                            "confidence": pat["confidence"],
                            "start": match.start(),
                            "end": match.end(),
                        }
                    )
            except re.error as e:
                logger.warning(f"Regex error for pattern {pat['name']}: {e}")
        return matches

    def match_sql_errors(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.sql_patterns)

    def match_command_output(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.command_patterns)

    def match_xss_reflection(self, text: str, payload: str = "") -> List[Dict[str, Any]]:
        matches = self._match_patterns(text, self.xss_patterns)
        if payload:
            escaped_payload = re.escape(payload)
            try:
                if re.search(escaped_payload, text, re.IGNORECASE):
                    matches.append(
                        {
                            "pattern_name": "reflected_payload",
                            "matched_text": payload,
                            "confidence": "definite",
                            "start": -1,
                            "end": -1,
                        }
                    )
            except re.error:
                pass
        return matches

    def match_ssti(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.ssti_patterns)

    def match_xxe(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.xxe_patterns)

    def match_ssrf(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.ssrf_patterns)

    def match_error_stacks(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.error_stack_patterns)

    def match_oob_indicators(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.oob_patterns)

    def match_lfi(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.lfi_patterns)

    def match_generic_indicators(self, text: str) -> List[Dict[str, Any]]:
        return self._match_patterns(text, self.generic_patterns)

    def match_all(self, text: str, payload: str = "") -> Dict[str, List[Dict[str, Any]]]:
        return {
            "sql_errors": self.match_sql_errors(text),
            "command_output": self.match_command_output(text),
            "xss_reflection": self.match_xss_reflection(text, payload),
            "ssti": self.match_ssti(text),
            "xxe": self.match_xxe(text),
            "ssrf": self.match_ssrf(text),
            "error_stacks": self.match_error_stacks(text),
            "oob_indicators": self.match_oob_indicators(text),
            "lfi": self.match_lfi(text),
            "generic": self.match_generic_indicators(text),
        }

    def get_pattern_count(self) -> Dict[str, int]:
        return {
            "sql": len(self.sql_patterns),
            "command": len(self.command_patterns),
            "xss": len(self.xss_patterns),
            "ssti": len(self.ssti_patterns),
            "xxe": len(self.xxe_patterns),
            "ssrf": len(self.ssrf_patterns),
            "error_stacks": len(self.error_stack_patterns),
            "oob": len(self.oob_patterns),
            "lfi": len(self.lfi_patterns),
            "generic": len(self.generic_patterns),
            "total": (
                len(self.sql_patterns)
                + len(self.command_patterns)
                + len(self.xss_patterns)
                + len(self.ssti_patterns)
                + len(self.xxe_patterns)
                + len(self.ssrf_patterns)
                + len(self.error_stack_patterns)
                + len(self.oob_patterns)
                + len(self.lfi_patterns)
                + len(self.generic_patterns)
            ),
        }
