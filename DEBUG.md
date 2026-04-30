# 点赞 403 调试记录

## Observations

- GitHub Actions 日志显示登录成功、页面成功识别到点赞按钮，但 `PUT /discourse-reactions/posts/{id}/custom-reactions/heart/toggle.json` 连续返回 403。
- 当前实现并不是真点页面按钮，而是先读取主题 JSON，再用 `curl_cffi` 的 `session.put(...)` 逐个对候选 `post_id` 发点赞请求。
- 用 `js-reverse` 连本地已登录 Chrome 现场验证后，真实页面点赞链路可以成功，且页面 DOM 自带 `meta[name='csrf-token']`。
- 真实 `toggle.json` 成功响应体里已包含 `current_user_reaction` / `current_user_used_main_reaction`，不需要再额外 `GET /posts/{id}` 确认。

## Hypotheses

### H1: GitHub Actions 上被拒绝的是外部 HTTP 重放链路，而非浏览器页面链路（ROOT HYPOTHESIS）
- Supports: Action 中 selector 已成功，但脚本自发的 `session.put(...)` 连续 403；本地真实页面点击可成功。
- Conflicts: 无关键冲突证据残留。
- Test: 已把点赞执行改为页面上下文 `fetch`，并用单测覆盖成功/403 重试语义。

### H2: `/session/csrf` 是多余且脆弱的一跳
- Supports: 本地真实页面 DOM 已有 csrf token；真实页面点赞不依赖额外 `/session/csrf` 请求。
- Conflicts: 无。
- Test: 已改为直接读取页面 `meta[name='csrf-token']`。

### H3: `GET /posts/{id}` 二次确认把已成功的点赞误判为失败
- Supports: `toggle.json` 响应体本身已经能确认当前用户反应状态。
- Conflicts: 无。
- Test: 已改为直接根据 `toggle.json` 返回体判成功。

## Experiments

- 已完成：使用 `js-reverse` 连本地已登录 Chrome，抓到真实 `PUT /discourse-reactions/posts/{id}/custom-reactions/heart/toggle.json` 成功请求与返回体。
- 已完成：验证页面存在 `meta[name='csrf-token']`。
- 已完成：将点赞执行改为页面上下文 `fetch`，并补单测验证成功、403 重试、缺失可见按钮时仍可按候选帖子执行。

## Root Cause

- GitHub Actions 上失败的不是页面登录态，而是脚本使用 `curl_cffi` 在浏览器上下文之外重放 `PUT toggle.json` 的点赞链路；这条链路会被服务端拒绝并返回 403。

## Fix

- 保留主题 JSON 的候选帖子筛选逻辑，避免误点已点赞帖子。
- 删除点赞主链对 `/session/csrf` 与 `GET /posts/{id}` 的依赖。
- 改为直接在页面上下文里读取 `meta[name='csrf-token']`，并用页面内 `fetch` 发送 `PUT /discourse-reactions/posts/{id}/custom-reactions/heart/toggle.json`。
- 直接依据 `toggle.json` 返回体中的 `current_user_reaction` / `current_user_used_main_reaction` 判定成功。
