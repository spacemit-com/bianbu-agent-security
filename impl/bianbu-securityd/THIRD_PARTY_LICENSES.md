# 第三方依赖许可证清单

本清单与 `requirements-lock.txt` 的精确版本绑定。版本升级必须重新确认上游
许可证，并重新生成 SBOM；不能仅依赖 wheel metadata（部分发行包不携带
License 字段）。

| 依赖 | 锁定版本 | 许可证依据 |
|------|----------|------------|
| cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause（上游 LICENSE） |
| dbus-python | 1.4.0 | MIT/X11 |
| PyGObject | 3.56.2 | LGPL-2.1-or-later |
| pytest | 9.1.1 | MIT |
| Flask | 3.1.3 | BSD-3-Clause |
| Flask-SocketIO | 5.6.1 | MIT |
| python-socketio | 5.16.4 | MIT |
| gunicorn | 26.0.0 | MIT |
| simple-websocket | 1.1.0 | MIT |
| langgraph | 1.2.10 | MIT |

该文件是发布审计输入，不替代各上游源码包中的完整许可证文本。
