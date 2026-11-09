# 实验07：软件安全检测与漏洞管理平台
## 项目说明
本项目基于OWASP ZAP 2.17.0扫描结果，使用Streamlit+SQLite搭建轻量漏洞管理平台，实现授权白名单门禁、扫描报告导入去重、漏洞状态流转、修复复扫完整闭环。
## 使用开源项目版本
- OWASP ZAP 2.17.0（被动扫描工具）
- Streamlit 1.65.0（Web界面）
- SQLite 3（本地数据库）
## 功能清单
1. 授权白名单强制校验：仅允许扫描localhost/127.0.0.1目标，公网地址直接拦截
2. ZAP JSON报告导入：自动解析告警，按规则ID+URL生成稳定指纹跨批次去重
3. 漏洞全生命周期管理：状态覆盖New/Confirmed/In Progress/Resolved/Verified全流程
4. Dashboard风险概览：展示风险等级分布、处置状态、扫描批次与修复率
5. 修复复扫对比：前后两次扫描自动比对，已修复漏洞绑定Commit后标记Verified
## 启动步骤
1. 进入platform目录激活虚拟环境
2. 运行 `streamlit run app.py`
3. 浏览器自动打开平台页面
## 修复闭环记录
- 已修复漏洞：缺少X-Frame-Options安全响应头，对应修复Commit: fix: add x-frame-options response header，复扫后告警消失，已标记Verified
