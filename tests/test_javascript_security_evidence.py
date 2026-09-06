"""Comprehensive Test Suite for JavaScript AST Security Evidence & Deterministic Rules.

Verifies:
1. DOM XSS detection (innerHTML, outerHTML, insertAdjacentHTML, template literals).
2. React dangerouslySetInnerHTML XSS detection.
3. Safe HTML literal exemptions.
4. Node.js child_process command injection (exec, execSync, require).
5. Safe spawn / non-shell command exemptions.
6. Disambiguation from generic regex/other .exec() calls.
7. Hardcoded secret detection with false-positive suppression (process.env, empty, short).
8. Analyzer contract (language, 1-indexed lines, deterministic evidence IDs, file_path).
9. Malformed JavaScript crash resilience.
10. Step 6O gate policy integration (HIGH/CRITICAL -> BLOCK, Clean -> ALLOW).
"""

from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.report_service import compute_review_status
from backend.analysis.security_gate import evaluate_security_gate


def _signals(source: str, file_path: str = "sample.js"):
    return analyze_javascript_security_structure(source, file_path=file_path)["security_signals"]


def _findings(source: str, file_path: str = "sample.js"):
    signals = _signals(source, file_path=file_path)
    return generate_deterministic_findings(signals)


# ===========================================================================
# 1. DOM XSS: innerHTML, outerHTML, insertAdjacentHTML
# ===========================================================================

def test_1_dom_xss_innerhtml_dynamic():
    source = "element.innerHTML = userInput;"
    signals = _signals(source)
    xss = [s for s in signals if s["signal_type"] == "dom_xss_call"]
    assert len(xss) == 1
    assert xss[0]["severity"] == "high"
    assert xss[0]["confidence"] == "high"
    assert xss[0]["category"] == "xss"


def test_2_dom_xss_innerhtml_static_literal_is_safe():
    source = 'element.innerHTML = "<p>Hello</p>";'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "dom_xss_call"]


def test_3_dom_xss_outerhtml_dynamic():
    source = "element.outerHTML = userInput;"
    signals = _signals(source)
    xss = [s for s in signals if s["signal_type"] == "dom_xss_call"]
    assert len(xss) == 1
    assert xss[0]["severity"] == "high"


def test_4_dom_xss_insertadjacenthtml_dynamic():
    source = 'element.insertAdjacentHTML("beforeend", userInput);'
    signals = _signals(source)
    xss = [s for s in signals if s["signal_type"] == "dom_xss_call"]
    assert len(xss) == 1
    assert xss[0]["severity"] == "high"


def test_5_dom_xss_insertadjacenthtml_static_literal_is_safe():
    source = 'element.insertAdjacentHTML("beforeend", "<p>safe</p>");'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "dom_xss_call"]


def test_6_dom_xss_template_substitution_dynamic():
    source = "element.innerHTML = `hello ${userInput}`;"
    signals = _signals(source)
    xss = [s for s in signals if s["signal_type"] == "dom_xss_call"]
    assert len(xss) == 1
    assert xss[0]["severity"] == "high"


def test_7_dom_xss_template_static_is_safe():
    source = "element.innerHTML = `hello static`;"
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "dom_xss_call"]


# ===========================================================================
# 2. React dangerouslySetInnerHTML
# ===========================================================================

def test_8_react_dangerously_set_inner_html_dynamic():
    source = "const comp = <div dangerouslySetInnerHTML={{ __html: userInput }} />;"
    signals = _signals(source)
    xss = [s for s in signals if s["signal_type"] == "dom_xss_call"]
    assert len(xss) == 1
    assert xss[0]["severity"] == "high"


def test_9_react_dangerously_set_inner_html_static_is_safe():
    source = 'const comp = <div dangerouslySetInnerHTML={{ __html: "<p>safe</p>" }} />;'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "dom_xss_call"]


# ===========================================================================
# 3. Node.js Command Execution
# ===========================================================================

def test_10_node_exec_dynamic():
    source = "child_process.exec(userInput);"
    signals = _signals(source)
    cmd = [s for s in signals if s["signal_type"] == "command_execution_call"]
    assert len(cmd) == 1
    assert cmd[0]["severity"] == "critical"
    assert cmd[0]["confidence"] == "high"
    assert cmd[0]["category"] == "command_execution"


def test_11_node_execsync_dynamic():
    source = "child_process.execSync(userInput);"
    signals = _signals(source)
    cmd = [s for s in signals if s["signal_type"] == "command_execution_call"]
    assert len(cmd) == 1
    assert cmd[0]["severity"] == "critical"


def test_12_node_require_exec_dynamic():
    source = 'require("child_process").exec(userInput);'
    signals = _signals(source)
    cmd = [s for s in signals if s["signal_type"] == "command_execution_call"]
    assert len(cmd) == 1
    assert cmd[0]["severity"] == "critical"


def test_13_node_require_execsync_dynamic():
    source = 'require("child_process").execSync(userInput);'
    signals = _signals(source)
    cmd = [s for s in signals if s["signal_type"] == "command_execution_call"]
    assert len(cmd) == 1
    assert cmd[0]["severity"] == "critical"


def test_14_regex_exec_is_not_command_injection():
    source = "regex.exec(userInput);"
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "command_execution_call"]


def test_15_other_exec_is_not_command_injection():
    source = "other.exec(userInput);"
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "command_execution_call"]


def test_16_node_spawn_is_out_of_scope_for_shell_injection():
    source = 'child_process.spawn("program", [userInput]);'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "command_execution_call"]


# ===========================================================================
# 4. Hardcoded Secrets
# ===========================================================================

def test_17_hardcoded_secret_detected():
    source = 'const apiKey = "sk-example-secret-key-12345";'
    signals = _signals(source)
    sec = [s for s in signals if s["signal_type"] == "possible_hardcoded_secret"]
    assert len(sec) == 1
    assert sec[0]["severity"] == "medium"
    assert sec[0]["category"] == "credential_management"


def test_18_secret_process_env_is_safe():
    source = "const token = process.env.API_TOKEN;"
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "possible_hardcoded_secret"]


def test_19_secret_config_call_is_safe():
    source = 'const apiKey = config.get("API_KEY");'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "possible_hardcoded_secret"]


def test_20_secret_empty_string_is_safe():
    source = 'const token = "";'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "possible_hardcoded_secret"]


def test_21_secret_short_placeholder_is_safe():
    source = 'const token = "test";'
    signals = _signals(source)
    assert not [s for s in signals if s["signal_type"] == "possible_hardcoded_secret"]


# ===========================================================================
# 5. Resilience & Analyzer Contract
# ===========================================================================

def test_22_malformed_javascript_does_not_crash():
    source = "function broken( { let x = ;"
    res = analyze_javascript_security_structure(source, file_path="broken.js")
    assert res["language"] == "javascript"
    assert res["parse_status"] == "has_errors"
    assert isinstance(res["security_signals"], list)


def test_23_analyzer_contract_properties_and_deterministic_ids():
    source = """
function render(userHtml, secretVal) {
    element.innerHTML = userHtml;
    const apiKey = "sk-production-live-key-99999";
}
"""
    res1 = analyze_javascript_security_structure(source, file_path="app.js")
    res2 = analyze_javascript_security_structure(source, file_path="app.js")

    assert res1["language"] == "javascript"
    assert res1["parse_status"] == "success"
    assert res1["file_path"] == "app.js"

    signals1 = res1["security_signals"]
    signals2 = res2["security_signals"]
    assert len(signals1) == 2

    # Deterministic evidence ID stability
    assert [s["evidence_id"] for s in signals1] == [s["evidence_id"] for s in signals2]

    # 1-indexed line numbers
    lines = [s["line"] for s in signals1]
    assert all(isinstance(l, int) and l >= 1 for l in lines)


# ===========================================================================
# 6. Step 6O Security Gate Authority Integration
# ===========================================================================

def test_24_dom_xss_high_triggers_block_gate():
    source = "element.innerHTML = userInput;"
    findings = _findings(source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["title"] == "Cross-Site Scripting (DOM XSS) Vulnerability"

    summary = {
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }
    report = {
        "status": "success",
        "review_status": compute_review_status(summary),
        "summary": summary,
        "findings": findings,
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


def test_25_node_command_critical_triggers_block_gate():
    source = "child_process.exec(userInput);"
    findings = _findings(source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["title"] == "Command Injection Risk"

    summary = {
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }
    report = {
        "status": "success",
        "review_status": compute_review_status(summary),
        "summary": summary,
        "findings": findings,
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


def test_26_clean_javascript_triggers_allow_gate():
    source = """
function greet(name) {
    console.log("Hello, " + name);
    return true;
}
"""
    findings = _findings(source)
    assert len(findings) == 0

    summary = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }
    report = {
        "status": "success",
        "review_status": compute_review_status(summary),
        "summary": summary,
        "findings": findings,
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "ALLOW"
    assert exit_code == 0


# ===========================================================================
# 7. JavaScript SQL Injection: Positive Detections
# ===========================================================================

def test_27_db_query_concatenation():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"
    assert sqli[0]["confidence"] == "high"
    assert sqli[0]["category"] == "sql_injection"
    assert sqli[0]["call_name"] == "db.query"


def test_28_db_execute_concatenation():
    source = 'db.execute("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "db.execute"


def test_29_database_query_concatenation():
    source = 'database.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "database.query"


def test_30_client_query_concatenation():
    source = 'client.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "client.query"


def test_31_pool_query_concatenation():
    source = 'pool.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "pool.query"


def test_32_connection_query_concatenation():
    source = 'connection.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "connection.query"


def test_33_conn_execute_concatenation():
    source = 'conn.execute("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "conn.execute"


def test_34_sequelize_query_concatenation():
    source = 'sequelize.query("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "sequelize.query"


def test_35_knex_raw_concatenation():
    source = 'knex.raw("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "knex.raw"


def test_36_prisma_queryraw_concatenation():
    source = 'prisma.$queryRaw("SELECT * FROM users WHERE id = " + userId);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "prisma.$queryRaw"


def test_37_prisma_executeraw_concatenation():
    source = 'prisma.$executeRaw("UPDATE users SET name = " + userName);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["call_name"] == "prisma.$executeRaw"


def test_38_template_interpolation_sql_injection():
    source = 'db.query(`SELECT * FROM users WHERE id = ${userId}`);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"


def test_39_multiple_concatenation_sql_injection():
    source = 'db.query("SELECT " + column + " FROM " + table + " WHERE id = " + id);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"


# ===========================================================================
# 8. JavaScript SQL: Safe Static Queries
# ===========================================================================

def test_40_static_select_is_safe():
    source = 'db.query("SELECT * FROM users");'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_41_static_insert_is_safe():
    source = 'db.query("INSERT INTO users (name) VALUES (\'alice\')");'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_42_static_update_is_safe():
    source = 'db.query("UPDATE users SET active = 1");'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_43_static_delete_is_safe():
    source = 'db.query("DELETE FROM users WHERE active = 0");'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_44_static_template_sql_is_safe():
    source = 'db.query(`SELECT * FROM users`);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


# ===========================================================================
# 9. JavaScript SQL: Safe Parameterized Queries
# ===========================================================================

def test_45_parameterized_query_qmark_is_safe():
    source = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_46_parameterized_query_dollar_is_safe():
    source = 'client.query("SELECT * FROM users WHERE id = $1", [userId]);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_47_parameterized_execute_is_safe():
    source = 'connection.execute("SELECT * FROM users WHERE id = ?", [userId]);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_48_parameterized_percent_s_is_safe():
    source = 'db.query("SELECT * FROM users WHERE id = %s", [userId]);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_49_parameterized_named_colon_is_safe():
    source = 'db.query("SELECT * FROM users WHERE id = :id", { id: userId });'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_50_parameterized_named_percent_is_safe():
    source = 'db.query("SELECT * FROM users WHERE id = %(id)s", { id: userId });'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


# ===========================================================================
# 10. Unsafe Dynamic SQL Despite Parameter List
# ===========================================================================

def test_51_dynamic_sql_with_param_array_remains_unsafe():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId, [userId]);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"


def test_52_client_query_dynamic_with_param_remains_unsafe():
    source = 'client.query("SELECT * FROM users WHERE id = " + userId, [userId]);'
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"


# ===========================================================================
# 11. Deferred Dynamic Cases & False-Positive Controls
# ===========================================================================

def test_53_bare_variable_query_is_deferred():
    source = 'db.query(queryVariable);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_54_function_generated_query_is_deferred():
    source = 'db.query(buildQuery(userId));'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_55_member_expression_query_is_deferred():
    source = 'db.query(request.body.query);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_56_logger_query_is_clean():
    source = 'logger.query(userInput);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_57_graphql_client_query_is_clean():
    source = 'graphqlClient.query(gqlQuery);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_58_search_index_query_is_clean():
    source = 'searchIndex.query(searchTerm);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_59_task_execute_is_clean():
    source = 'task.execute(context);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_60_workflow_execute_is_clean():
    source = 'workflow.execute(step);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_61_regex_exec_is_clean():
    source = 'regex.exec(userInput);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_62_custom_object_query_is_clean():
    source = 'myCustomObj.query(userInput);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_63_mydb_substring_receiver_is_clean():
    source = 'mydb.query("SELECT * FROM users WHERE id = " + id);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_64_dbclient_substring_receiver_is_clean():
    source = 'dbClient.query("SELECT * FROM users WHERE id = " + id);'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


def test_65_other_database_apis_out_of_scope():
    assert not [s for s in _signals('db.run("SELECT ..." + id);') if s["signal_type"] == "unsafe_database_execution"]
    assert not [s for s in _signals('db.get("SELECT ..." + id);') if s["signal_type"] == "unsafe_database_execution"]
    assert not [s for s in _signals('db.all("SELECT ..." + id);') if s["signal_type"] == "unsafe_database_execution"]
    assert not [s for s in _signals('db.prepare("SELECT ..." + id);') if s["signal_type"] == "unsafe_database_execution"]


def test_66_prisma_tagged_template_is_deferred():
    source = 'prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;'
    assert not [s for s in _signals(source) if s["signal_type"] == "unsafe_database_execution"]


# ===========================================================================
# 12. Robustness, Determinism & Pipeline Integration
# ===========================================================================

def test_67_malformed_js_with_sql_does_not_crash():
    source = 'db.query("SELECT " + ;'
    res = analyze_javascript_security_structure(source, file_path="broken.js")
    assert res["language"] == "javascript"
    assert res["parse_status"] == "has_errors"
    assert isinstance(res["security_signals"], list)


def test_68_empty_js_returns_clean():
    res = analyze_javascript_security_structure("", file_path="empty.js")
    assert res["parse_status"] == "success"
    assert res["security_signals"] == []


def test_69_multiline_dynamic_sql_is_detected():
    source = """
db.query(
    "SELECT * " +
    "FROM users " +
    "WHERE id = " + userId
);
"""
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1


def test_70_nested_sql_sink_in_callback():
    source = """
function fetchUser(req, res) {
    const id = req.params.id;
    setTimeout(() => {
        db.query("SELECT * FROM users WHERE id = " + id);
    }, 100);
}
"""
    signals = _signals(source)
    sqli = [s for s in signals if s["signal_type"] == "unsafe_database_execution"]
    assert len(sqli) == 1
    assert sqli[0]["line"] >= 5


def test_71_sql_determinism_identical_ids():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId);'
    s1 = _signals(source, file_path="query.js")
    s2 = _signals(source, file_path="query.js")
    assert len(s1) == 1 and len(s2) == 1
    assert s1[0]["evidence_id"] == s2[0]["evidence_id"]


def test_72_sql_determinism_different_line():
    s1 = _signals('db.query("SELECT * FROM users WHERE id = " + userId);', file_path="query.js")
    s2 = _signals('\n\ndb.query("SELECT * FROM users WHERE id = " + userId);', file_path="query.js")
    assert s1[0]["evidence_id"] != s2[0]["evidence_id"]


def test_73_sql_determinism_different_file():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId);'
    s1 = _signals(source, file_path="a.js")
    s2 = _signals(source, file_path="b.js")
    assert s1[0]["evidence_id"] != s2[0]["evidence_id"]


def test_74_sql_canonical_finding_conversion():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId);'
    findings = _findings(source, file_path="db.js")
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "Potential SQL Injection Vulnerability"
    assert f["category"] == "Injection"
    assert f["severity"] == "high"


def test_75_sql_triggers_security_gate_block():
    source = 'db.query("SELECT * FROM users WHERE id = " + userId);'
    findings = _findings(source)
    assert len(findings) == 1

    summary = {
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }
    report = {
        "status": "success",
        "review_status": compute_review_status(summary),
        "summary": summary,
        "findings": findings,
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1
