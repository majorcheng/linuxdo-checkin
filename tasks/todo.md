- [x] 复核线上 `main` 与本地 `HEAD` 一致，确认当前基线可直接调试
- [x] 用 `js-reverse` 连已登录 Chrome，验证真实点赞链路与 403 现象
- [x] 将点赞执行从 `curl_cffi` 外部重放改为页面上下文 `fetch`
- [x] 移除点赞主链对 `/session/csrf` 与 `GET /posts/{id}` 的额外依赖
- [x] 更新点赞相关单测，覆盖页面上下文点赞成功与 403 重试
- [x] 运行最小充分验证并记录结果

## 复盘小结

- 根因不是登录，也不是按钮 selector，而是 GitHub Actions 上的外部 HTTP 重放点赞链路会被服务端 403 拒绝。
- 保留主题 JSON 候选筛选可以继续避免误把旧赞点成取消赞；真正需要替换的是执行口径。
- 当前最小修复是让候选 `post_id` 仍来自主题 JSON，但真正的 `PUT toggle.json` 改为在页面上下文里执行，并直接依据返回体判成功。
- 验证结果：`python -m py_compile main.py tests/test_like_behavior.py` 通过，`python -m pytest -q` 为 `31 passed`。
