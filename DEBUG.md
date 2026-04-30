# 点赞 403 调试记录

## Observations

- GitHub Actions 日志显示登录成功、页面成功识别到点赞按钮，但点赞 API 会返回 403。
- 第一轮改成页面上下文 `fetch` 后，返回体不再是空，而是 Cloudflare challenge HTML（`Just a moment...`）。
- 第二轮改成候选楼层真实按钮点击后，Action 现场日志表明原生点击总被页面遮挡，随后退回 `DOM click`，最终仍触发 challenge。
- 这说明失败的不只是外部 `curl_cffi` 重放，连页面内裸 `fetch` 与 `DOM click` 也不是站点认可的真实交互链；真正的问题是必须完成可信的 pointer click。

## Hypotheses

### H1: GitHub Actions 上被拒绝的是“非可信点击”的点赞链，而不是登录态本身（ROOT HYPOTHESIS）
- Supports: selector 成功、主题 JSON 成功；外部 `session.put(...)`、页面内裸 `fetch(...)` 和 `DOM click` 触发的请求都会落到 403/challenge；现场日志明确显示原生点击总被遮挡。
- Conflicts: 无关键冲突证据残留。
- Test: 已禁用 `DOM click` 兜底，只允许重定位后的真实 pointer click 成功，否则跳下一个候选。

### H2: 主题 JSON 候选筛选仍然有价值，问题只在执行口径
- Supports: 候选筛选能避免误把旧赞点成取消赞；失败集中发生在请求链而非筛选链。
- Conflicts: 无。
- Test: 已保留筛选逻辑，只替换执行方式。

## Experiments

- 已完成：使用 `js-reverse` 连本地已登录 Chrome，抓到真实页面点赞链路与 `Just a moment...` challenge 现象。
- 已完成：验证页面上下文裸 `fetch` 仍会被 challenge。
- 已完成：将点赞执行切换为候选按钮真实点击，补齐候选楼层缺失、403 重试、指针遮挡重定位、禁用 `DOM click` 退路等单测。

## Root Cause

- GitHub Actions 上失败的不是登录态，而是脚本自己构造的点赞请求链路；无论是外部 `curl_cffi` 重放、页面内裸 `fetch`，还是在原生点击失败后退回 `DOM click`，都可能被 Cloudflare/站点风控拒绝。真正更接近现场成功行为的是点击候选楼层对应的真实页面按钮，并确保它走的是可信 pointer click，而不是程序化点击兜底。

## Fix

- 保留主题 JSON 候选帖子筛选逻辑，只对未点赞候选帖子尝试操作。
- 删除页面内裸 `fetch` 主线，改为在当前 DOM 中匹配候选 `post_id` 对应的真实点赞按钮并点击。
- 点击时保留滚动到安全位置、等待页面稳定、拦截响应，并在被遮挡时重新定位后重试真实点击。
- 彻底禁用 `DOM click` 兜底；若候选按钮持续被遮挡，则干净失败并切到下一个候选。
- 直接依据真实按钮触发后的网络响应内容判断成功；候选楼层不在当前 DOM 时跳过到下一个候选。
