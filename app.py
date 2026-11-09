import streamlit as st
import sqlite3
import json
import hashlib
from datetime import datetime

# 授权白名单，只允许扫本地目标
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "host.docker.internal"}

# 初始化数据库
def init_db():
    conn = sqlite3.connect("vuln.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (fingerprint TEXT PRIMARY KEY,
                  rule_id TEXT,
                  risk TEXT,
                  name TEXT,
                  url TEXT,
                  description TEXT,
                  solution TEXT,
                  status TEXT DEFAULT 'New',
                  assignee TEXT DEFAULT '',
                  first_seen TEXT,
                  last_seen TEXT,
                  fix_commit TEXT DEFAULT '',
                  notes TEXT DEFAULT '')''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_type TEXT,
                  target TEXT,
                  scan_time TEXT,
                  report_data TEXT)''')
    conn.commit()
    conn.close()

# 生成漏洞稳定指纹
def make_fingerprint(rule_id, url, param=""):
    normalized_url = url.split("?")[0].rstrip("/")
    raw = f"{rule_id}|{normalized_url}|{param}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

# 白名单校验
def check_whitelist(target_url):
    host = target_url.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    return host in ALLOWED_HOSTS

st.set_page_config(page_title="漏洞管理平台", layout="wide")
init_db()

st.title("软件安全检测与漏洞管理平台")
st.warning("⚠️ 仅允许扫描localhost/127.0.0.1授权本地目标，禁止扫描公网资产")

# 侧边栏功能
page = st.sidebar.radio("功能导航", ["Dashboard", "导入扫描报告", "漏洞列表", "白名单授权管理"])

if page == "白名单授权管理":
    st.header("授权范围白名单")
    st.write(f"当前允许扫描的主机：{', '.join(ALLOWED_HOSTS)}")
    test_url = st.text_input("测试目标地址", "http://127.0.0.1:8001")
    if st.button("校验目标"):
        if check_whitelist(test_url):
            st.success(f"✅ 目标 {test_url} 在授权白名单内，允许扫描")
        else:
            st.error(f"❌ 目标 {test_url} 不在白名单内，已拒绝扫描")

elif page == "导入扫描报告":
    st.header("导入ZAP扫描报告")
    scan_type = st.selectbox("扫描批次", ["before", "after"])
    target = st.text_input("扫描目标", "http://127.0.0.1:8001")
    uploaded_file = st.file_uploader("上传ZAP JSON报告", type=["json"])
    if st.button("导入报告"):
        if not check_whitelist(target):
            st.error("目标不在白名单，导入终止")
            st.stop()
        if uploaded_file is None:
            st.info("无真实报告文件时，自动生成测试基线数据")
            test_alerts = [
                {"rule_id":"10020","risk":"Low","name":"X-Frame-Options Header Not Set","url":"/","desc":"缺少X-Frame-Options头，存在点击劫持风险","solution":"添加X-Frame-Options: DENY响应头"},
                {"rule_id":"10021","risk":"Low","name":"X-Content-Type-Options Header Missing","url":"/","desc":"缺少X-Content-Type-Options头","solution":"添加X-Content-Type-Options: nosniff响应头"},
                {"rule_id":"10038","risk":"Medium","name":"Content Security Policy Header Not Set","url":"/","desc":"缺少CSP安全响应头","solution":"配置合理的Content-Security-Policy响应头"},
                {"rule_id":"2","risk":"Low","name":"Cookie No HttpOnly Flag","url":"/reserve","desc":"Cookie未设置HttpOnly属性","solution":"给Cookie添加HttpOnly标记"},
                {"rule_id":"10096","risk":"Info","name":"TLS Certificate Information","url":"/","desc":"TLS证书信息泄露","solution":"生产环境关闭调试信息"}
            ]
        else:
            report = json.load(uploaded_file)
            test_alerts = []
            for site in report.get("site",[]):
                for alert in site.get("alerts",[]):
                    test_alerts.append({
                        "rule_id": str(alert.get("pluginid","")),
                        "risk": alert.get("riskdesc","").split(" ")[0],
                        "name": alert.get("name",""),
                        "url": alert.get("instances",[{}])[0].get("uri",""),
                        "desc": alert.get("desc",""),
                        "solution": alert.get("solution","")
                    })
        conn = sqlite3.connect("vuln.db")
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_count = 0
        for a in test_alerts:
            fp = make_fingerprint(a["rule_id"], a["url"])
            c.execute("SELECT fingerprint FROM findings WHERE fingerprint=?", (fp,))
            if c.fetchone() is None:
                c.execute('''INSERT INTO findings 
                            (fingerprint, rule_id, risk, name, url, description, solution, first_seen, last_seen)
                            VALUES (?,?,?,?,?,?,?,?,?)''',
                            (fp, a["rule_id"], a["risk"], a["name"], a["url"], a["desc"], a["solution"], now, now))
                new_count +=1
            else:
                c.execute("UPDATE findings SET last_seen=? WHERE fingerprint=?", (now, fp))
        c.execute("INSERT INTO scans (scan_type, target, scan_time, report_data) VALUES (?,?,?,?)",
                  (scan_type, target, now, "imported"))
        conn.commit()
        conn.close()
        st.success(f"导入完成，新增{new_count}条漏洞，重复条目自动去重")

elif page == "漏洞列表":
    st.header("漏洞处置列表")
    conn = sqlite3.connect("vuln.db")
    c = conn.cursor()
    c.execute("SELECT * FROM findings ORDER BY CASE risk WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END")
    rows = c.fetchall()
    st.write(f"共 {len(rows)} 条漏洞记录")
    for row in rows:
        fp, rule_id, risk, name, url, desc, sol, status, assignee, first, last, commit, notes = row
        with st.expander(f"[{risk}] {name} - {status}"):
            st.write(f"规则ID: {rule_id} | URL: {url}")
            st.write(f"描述: {desc}")
            st.write(f"修复建议: {sol}")
            col1, col2, col3 = st.columns(3)
            with col1:
                new_status = st.selectbox("状态", ["New","Confirmed","False Positive","Accepted Risk","In Progress","Resolved","Verified"],
                                          index=["New","Confirmed","False Positive","Accepted Risk","In Progress","Resolved","Verified"].index(status),
                                          key=f"st_{fp}")
            with col2:
                new_assignee = st.text_input("负责人", assignee, key=f"as_{fp}")
            with col3:
                new_commit = st.text_input("修复Commit", commit, key=f"cm_{fp}")
            if st.button("保存修改", key=f"sv_{fp}"):
                c.execute("UPDATE findings SET status=?, assignee=?, fix_commit=? WHERE fingerprint=?",
                          (new_status, new_assignee, new_commit, fp))
                conn.commit()
                st.rerun()
    conn.close()

elif page == "Dashboard":
    st.header("风险概览Dashboard")
    conn = sqlite3.connect("vuln.db")
    c = conn.cursor()
    c.execute("SELECT risk, COUNT(*) FROM findings GROUP BY risk")
    risk_data = c.fetchall()
    c.execute("SELECT status, COUNT(*) FROM findings GROUP BY status")
    status_data = c.fetchall()
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("风险等级分布")
        for r,cnt in risk_data:
            st.write(f"{r}: {cnt} 条")
    with col2:
        st.subheader("处置状态分布")
        for s,cnt in status_data:
            st.write(f"{s}: {cnt} 条")
    st.subheader("修复复扫对比")
    c.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    scan_data = c.fetchall()
    st.write(f"已完成扫描批次：{dict(scan_data)}")
    c.execute("SELECT COUNT(*) FROM findings WHERE status='Verified'")
    closed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM findings")
    total = c.fetchone()[0]
    st.success(f"已验证关闭漏洞：{closed}/{total}")
    conn.close()
