- [x] 复核线上 `main` 与本地 `HEAD` 一致，确认当前基线可直接调试
- [x] 用 `js-reverse` 连已登录 Chrome，验证真实点赞链路与 403 / challenge 现象
- [x] 将点赞执行从外部 `curl_cffi` 重放切到候选楼层对应的真实按钮点击
- [x] 去掉 `DOM click` 兜底，只允许真实 pointer click 成功或干净失败后切到下一个候选
- [x] 更新点赞相关单测，覆盖候选楼层缺失、403 重试、遮挡重定位与禁用 DOM click 退路
- [x] 运行最小充分验证并记录结果
- [x] 复核最新 Action 现场日志，确认真实点击已发生但仍返回 Cloudflare challenge HTML
- [x] 将 CI 浏览器模式改为显式可配置，并在 GitHub Actions 上切到 headed + real Chrome
- [x] 为浏览器模式开关补单测，并重新跑 `py_compile` / `pytest`
- [x] 推送 headed + real Chrome 修复并手动触发新的 `Daily Check-in`
- [x] 跟踪 headed + real Chrome 回归日志，确认浏览器模式切换已生效但点赞仍未成功
- [x] 移除 Action 代理出口并再次触发 `Daily Check-in`，确认 runner 直连会在主页持续命中 429
- [x] 为点赞 403 challenge 增加显式恢复与同一候选单次重试，并补单测
- [ ] 恢复代理浏览前提后再次触发 `Daily Check-in`，验证 challenge 恢复链路是否能打通点赞
- [ ] 跟踪最新 workflow 日志，确认出现至少一次“点赞成功”

## 复盘小结

- 根因不是登录，也不是 selector，而是 Cloudflare/站点会拒绝脚本构造的点赞请求链路；即使页面内裸 `fetch` 也仍会被 challenge。
- 第二轮已经把执行口径改成真实按钮点击，但 Action 现场日志表明真实点击总被遮挡，随后退回 `DOM click`，最终仍被 challenge。
- 第三轮最小修复是：保留主题 JSON 候选筛选，但彻底禁用 `DOM click` 退路；若按钮被遮挡，则重新定位后重试真实点击，仍失败就切下一个候选。
- 最新证据显示，在清理遮挡弹窗后，Action 中的真实点击已经能稳定发出请求，但仍收到 `403 / Just a moment...`，根因进一步收敛到 CI 浏览器环境本身。
- `headed + real Chrome + xvfb-run` 已在 Action 中生效，但 challenge 仍然存在；这否定了“只要摆脱 headless Chromium 就能成功”的假设。
- runner 直连会在主页持续命中 `429`，因此代理浏览前提不能去掉；这否定了“直接去代理就能收口”的假设。
- 当前轮次新的最小实验是：保留代理浏览前提，但在点赞命中 `403 / Just a moment...` 后显式执行一次 Cloudflare 恢复，再重试同一候选帖子。
