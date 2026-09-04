"""Stage 7A deterministic AST security evidence regression coverage."""

from ast_engine.security_analyzer import analyze_security_structure


def _signals(source: str):
    return analyze_security_structure(source, file_path="sample.py")["security_signals"]


def test_parameterized_sql_is_not_sql_injection_evidence():
    signals = _signals('def get(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))')
    assert not [signal for signal in signals if signal["category"] == "sql_injection"]


def test_dynamic_sql_concatenation_and_f_string_are_detected():
    concat = _signals('def get(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
    fstring = _signals('def get(cursor, user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
    assert concat[0]["signal_type"] == "unsafe_database_execution"
    assert concat[0]["severity"] == "high"
    assert fstring[0]["signal_type"] == "unsafe_database_execution"


def test_command_execution_distinguishes_shell_and_argument_vector():
    fixed = _signals('def run():\n    os.system("date")')
    dynamic = _signals('def run(user_input):\n    os.system(user_input)')
    safe_vector = _signals('def run():\n    subprocess.run(["git", "status"], shell=False)')
    assert fixed[0]["severity"] == "medium"
    assert dynamic[0]["severity"] == "critical"
    assert safe_vector[0]["argument_assessment"]["shell"] is False
    assert safe_vector[0]["severity"] == "medium"


def test_dynamic_execution_and_hardcoded_secret_remain_detected():
    signals = _signals('def run(user_input):\n    api_key = "not-a-real-secret"\n    eval(user_input)\n    exec(user_input)')
    assert sum(signal["signal_type"] == "dynamic_code_execution" for signal in signals) == 2
    assert all(signal["severity"] == "critical" for signal in signals if signal["signal_type"] == "dynamic_code_execution")
    assert any(signal["signal_type"] == "possible_hardcoded_secret" for signal in signals)


def test_credential_flow_to_authorization_header_is_medium():
    signals = _signals('def headers(auth_token):\n    api_key = auth_token\n    return {"Authorization": f"Bearer {api_key}"}')
    flow = [signal for signal in signals if signal["signal_type"] == "credential_propagation_to_authorization_sink"]
    assert len(flow) == 1
    assert flow[0]["severity"] == "medium"
    assert flow[0]["file_path"] == "sample.py"
    assert len(flow[0]["evidence_id"]) == 64
