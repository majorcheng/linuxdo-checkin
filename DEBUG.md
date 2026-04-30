# 点赞 403 调试记录

## Observations

- GitHub Actions 日志显示登录成功、页面成功识别到点赞按钮，但点赞 API 会返回 403。
- 第一轮改成页面上下文 `fetch` 后，返回体不再是空，而是 Cloudflare challenge HTML（`Just a moment...`）。
- 第二轮改成候选楼层真实按钮点击后，Action 现场日志表明原生点击总被页面遮挡，随后退回 `DOM click`，最终仍触发 challenge。
- 第三轮去掉 `DOM click`、补了遮挡重定位和阻塞弹窗清理后，Action 日志里不再出现“降级为 DOM click”，而是直接对真实按钮点击后的 `toggle.json` 收到 `403 / Just a moment...`。
- 当前 `main.py` 仍通过 Scrapling `StealthySession(headless=True, real_chrome=False)` 启动浏览器；而我此前用本地真实 Chrome 做 live 对照时，真实点赞链路可成功。
- 将 Action 切到 `headed + real Chrome` 后，日志已确认 `headless=0, real_chrome=1`，但点赞请求依然返回 challenge；同一轮日志同时显示 `proxy=on`，且代理是 `https://` 出口。
- 这说明失败的不只是外部 `curl_cffi` 重放，连页面内裸 `fetch` 与 `DOM click` 也不是站点认可的真实交互链；在可信 pointer click 已成立后，剩余差异进一步收敛到 CI 浏览器环境本身。

## Hypotheses

### H1: GitHub Actions 上被拒绝的是“无效执行口径”的点赞链，而不是登录态本身
- Supports: selector 成功、主题 JSON 成功；外部 `session.put(...)`、页面内裸 `fetch(...)` 和 `DOM click` 触发的请求都会落到 403/challenge。
- Conflicts: 经过真实按钮点击与弹窗清理后，请求仍然被 challenge，说明这已不是当前最靠近根因的层面。
- Test: 已完成，结论是仅修执行口径不足以解决 CI 现场 challenge。

### H2: 主题 JSON 候选筛选仍然有价值，问题只在执行口径
- Supports: 候选筛选能避免误把旧赞点成取消赞；失败集中发生在请求链而非筛选链。
- Conflicts: 无。
- Test: 已保留筛选逻辑，只替换执行方式。

### H3: GitHub Actions 里的 headless Chromium 浏览器环境仍会触发 Cloudflare challenge（ROOT HYPOTHESIS）
- Supports: 当前 Action 已能完成真实按钮点击，但 `toggle.json` 仍返回 challenge HTML；`main.py` 仍固定 `headless=True`、`real_chrome=False`；本地已验证成功的是已登录真实 Chrome。
- Conflicts: 已在 GitHub Actions 上直接验证 `headed + real Chrome`，challenge 仍然存在。
- Test: 在 workflow 中显式切到 `xvfb-run + headed + real Chrome`，并让 `main.py` 输出当前浏览器模式后再跑一轮 `Daily Check-in`。

### H4: GitHub Actions 使用的代理出口触发了 Cloudflare 对点赞请求的更严格挑战（ROOT HYPOTHESIS）
- Supports: 切到 `headed + real Chrome` 后仍是 challenge；最新日志明确记录 `proxy=on`；我本地成功样本是无此 Action 代理的真实 Chrome；同仓库日志里还出现过主题 JSON 超时，代理链路本身存在不稳定迹象。
- Conflicts: 还没有在 GitHub Actions 上直接验证“去代理直连 runner 出口”能否让点赞成功。
- Test: 暂时移除 workflow 中的 `LINUXDO_PROXY_URL` / `LINUXDO_PROXY_INSECURE`，保持其余条件不变，再跑一轮 `Daily Check-in`。

## Experiments

- 已完成：使用 `js-reverse` 连本地已登录 Chrome，抓到真实页面点赞链路与 `Just a moment...` challenge 现象。
- 已完成：验证页面上下文裸 `fetch` 仍会被 challenge。
- 已完成：将点赞执行切换为候选按钮真实点击，补齐候选楼层缺失、403 重试、指针遮挡重定位、禁用 `DOM click` 退路等单测。
- 已完成：清理阻塞点赞的 Discourse 弹窗，确认 Action 现场不再依赖 `DOM click`，但真实点击后的响应仍是 `403 / Just a moment...`。
- 已完成：将 GitHub Actions 浏览器运行模式切到 `headed + real Chrome + xvfb-run`，但 challenge 仍存在，H3 被否定。
- 进行中：移除 workflow 里的代理出口，验证 runner 直连是否能打通点赞请求。

## Root Cause

- 当前已确认的根因分两层：第一层是脚本构造请求链路会被 challenge，因此必须走候选楼层真实按钮点击；第二层已经从“headless Chromium 差异”进一步收敛到“GitHub Actions 当前代理出口仍会触发 Cloudflare challenge”，后者仍待 runner 直连回归最终确认。

## Fix

- 已完成：保留主题 JSON 候选帖子筛选逻辑，只对未点赞候选帖子尝试操作。
- 已完成：删除页面内裸 `fetch` 主线，改为在当前 DOM 中匹配候选 `post_id` 对应的真实点赞按钮并点击。
- 已完成：点击时保留滚动到安全位置、等待页面稳定、拦截响应，并在被遮挡时重新定位后重试真实点击。
- 已完成：彻底禁用 `DOM click` 兜底；若候选按钮持续被遮挡，则干净失败并切到下一个候选。
- 已完成：为浏览器启动增加显式 `LINUXDO_BROWSER_HEADLESS` / `LINUXDO_BROWSER_REAL_CHROME` 开关，并已在 GitHub Actions 中验证 `xvfb-run + headed + real Chrome` 生效。
- 进行中：将 GitHub Actions 的点赞链路临时改走 runner 直连，验证代理是否就是剩余的 challenge 根因。
