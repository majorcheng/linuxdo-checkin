- [x] 复核线上 `main` 与本地 `HEAD` 一致，确认当前基线可直接调试
- [x] 用 `js-reverse` 连已登录 Chrome，验证真实点赞链路与 403 现象
- [x] 将点赞执行从外部 `curl_cffi` 重放切到页面内真实按钮点击
- [x] 保留主题 JSON 候选筛选，避免把已点赞帖子误点成取消赞
- [x] 更新点赞相关单测，覆盖候选楼层缺失、403 重试与真实按钮点击
- [x] 运行最小充分验证并记录结果

## 复盘小结

- 根因不是登录，也不是 selector，而是 Cloudflare/站点会拒绝脚本构造的点赞请求链路；即使页面内裸 `fetch` 也仍会被 challenge。
- 这次最小可行修复是：继续用主题 JSON 决定“谁能点”，但真正“怎么点”改成点击候选 `post_id` 对应的真实页面按钮。
- 这样既保留了避免误取消旧赞的筛选保护，又贴近真实页面交互链。
- 验证结果：`python -m py_compile main.py tests/test_like_behavior.py` 通过，`python -m pytest -q` 为 `33 passed`。
