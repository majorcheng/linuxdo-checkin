# LinuxDo 每日签到（每日打卡）

## 项目描述

这个项目用于自动登录 [LinuxDo](https://linux.do/) 网站并随机读取几个帖子。它使用 Python 和 Scrapling
浏览器运行栈完成登录态校验、签到前浏览与帖子访问，以达到自动签到的功能。

有时会登录失败，重试一下就行了，嫌失败邮件通知烦的可以吧action的邮件通知关了

## 运行架构说明

当前主运行栈已从 `DrissionPage` 切换到 `Scrapling`。

- CI / 本地首次安装 Python 依赖后，需要额外执行一次 `scrapling install`，用于准备 Scrapling 所需的浏览器运行时。
- `LINUXDO_PROXY_URL` / `LINUXDO_PROXY_INSECURE` 的代理语义保持不变，仍然只影响浏览器访问 Linux.do 的出口链路。
- README 中旧的 DrissionPage / Playwright 表述已不再适用，后续登录与浏览链路都以 Scrapling 运行时为准。

## 功能

- 自动登录`LinuxDo`。
- 自动浏览帖子。
- 每天在`GitHub Actions`中自动运行。
- 支持`青龙面板` 和 `Github Actions` 自动运行。
- 当前运行栈基于`Scrapling`，不再依赖`DrissionPage`。
- (可选)`Telegram`通知功能，推送获取签到结果（目前只支持GitHub Actions方式）。
- (可选)`Gotify`通知功能，推送获取签到结果。
- (可选)`Server酱³`通知功能，推送获取签到结果。
- (可选)`wxpush`通知功能，推送获取签到结果。
## 环境变量配置

### 登录方式（二选一）

**方式一：Cookie 登录（优先）**

| 环境变量名称             | 描述                                         | 示例值                          |
|--------------------|--------------------------------------------|------------------------------|
| `LINUXDO_COOKIES`  | 从浏览器 DevTools 复制的主站 Cookie 字符串，设置后优先使用，无需账号密码 | `_t=xxx; _forum_session=yyy` |

> 获取方式：打开 [linux.do](https://linux.do/) 并登录 → 按 F12 → Application → Cookies → `https://linux.do` → 全选所有 Cookie 复制为字符串粘贴即可。
>
> 如需让脚本同时读取 `connect.linux.do` 的登录态，可额外配置可选变量 `LINUXDO_CONNECT_COOKIES`，把 `https://connect.linux.do` 下的 Cookie 单独传入。这个变量适合补充 `auth.session-token`、`linux_do_credit_session_id`、`__stripe_sid` 这类 Connect 域专属 Cookie。
> `connect.linux.do` 检查默认**不参与主流程**；只有在设置 `LINUXDO_CONNECT_INFO_ENABLED=true` 时，才会额外输出 Connect 调试信息。

**方式二：账号密码登录**

| 环境变量名称             | 描述                | 示例值                                |
|--------------------|-------------------|------------------------------------|
| `LINUXDO_USERNAME` | 你的 LinuxDo 用户名或邮箱 | `your_username` 或 `your@email.com` |
| `LINUXDO_PASSWORD` | 你的 LinuxDo 密码     | `your_password`                    |

> 若同时设置了 `LINUXDO_COOKIES` 和账号密码，**Cookie 登录优先**；Cookie 失效时自动回退到账号密码登录。

~~之前的USERNAME和PASSWORD环境变量仍然可用，但建议使用新的环境变量~~

### 可选变量

| 环境变量名称                | 描述                   | 示例值                                    |
|----------------------|----------------------|----------------------------------------|
| `GOTIFY_URL`         | Gotify 服务器地址         | `https://your.gotify.server:8080`      |
| `GOTIFY_TOKEN`       | Gotify 应用的 API Token | `your_application_token`               |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot Token   | `123456789:ABCdefghijklmnopqrstuvwxyz` |
| `TELEGRAM_CHAT_ID`   | Telegram 用户 ID       | `123456789`                            |
| `SC3_PUSH_KEY`       | Server酱³ SendKey     | `sctpxxxxt`                            |
| `WXPUSH_URL`         | wxpush 服务器地址         | `https://your.wxpush.server`           |
| `WXPUSH_TOKEN`       | wxpush 的 token       | `your_wxpush_token`                    |
| `BROWSE_ENABLED`     | 是否启用浏览帖子功能           | `true` 或 `false`，默认为 `true`           |
| `LINUXDO_PROXY_URL`  | 上游代理地址，支持 `http://` 或 `https://`，也支持账号密码代理 | `https://user:pass@proxy.example.com:8443` |
| `LINUXDO_PROXY_INSECURE` | 是否跳过“连接上游 HTTPS 代理”这一跳的证书校验 | `true` 或 `false`；当 `LINUXDO_PROXY_URL` 是 `https://` 时默认 `true` |
| `LINUXDO_CONNECT_COOKIES` | `connect.linux.do` 的附加 Cookie 字符串，用于补充 Connect 域专属登录态 | `auth.session-token=xxx; linux_do_credit_session_id=yyy` |

> 当 `LINUXDO_PROXY_URL` 使用 `https://` 时，脚本默认按 `LINUXDO_PROXY_INSECURE=true` 处理；如需严格校验证书，请显式设置 `LINUXDO_PROXY_INSECURE=false`。该开关**只影响连接上游 HTTPS 代理时的证书校验**，不会关闭 `linux.do` 本站的 HTTPS 校验。

---

## 如何使用

### GitHub Actions 自动运行

此项目的 GitHub Actions 配置会自动每天运行2次签到脚本。你无需进行任何操作即可启动此自动化任务。GitHub Actions 的工作流文件位于 `.github/workflows` 目录下，文件名为 `daily-check-in.yml`。

工作流首次运行时会依次执行：

1. `pip install -r requirements.txt`
2. `scrapling install`
3. `python main.py`

#### 配置步骤

1. **设置环境变量**：
    - 在 GitHub 仓库的 `Settings` -> `Secrets and variables` -> `Actions` 中添加以下变量：
        - （二选一）`LINUXDO_COOKIES`：从浏览器复制的主站 Cookie 字符串（**推荐，优先使用**）。
        - (可选) `LINUXDO_CONNECT_COOKIES`：从 `https://connect.linux.do` 复制的附加 Cookie 字符串，用于补充 Connect 域专属 Cookie。
        - （二选一）`LINUXDO_USERNAME` + `LINUXDO_PASSWORD`：你的 LinuxDo 用户名/邮箱和密码。
        - (可选) `BROWSE_ENABLED`：是否启用浏览帖子，`true` 或 `false`，默认为 `true`。
        - (可选) `LINUXDO_PROXY_URL`：代理地址，支持 `http://` / `https://` / 账号密码代理。
        - (可选) `LINUXDO_PROXY_INSECURE`：设为 `true` 时，仅跳过连接上游 HTTPS 代理这一跳的证书校验。
        - (可选) `GOTIFY_URL` 和 `GOTIFY_TOKEN`。
        - (可选) `SC3_PUSH_KEY`。
        - (可选) `WXPUSH_URL` 和 `WXPUSH_TOKEN`。
        - (可选) `TELEGRAM_BOT_TOKEN` 和 `TELEGRAM_CHAT_ID`。

2. **手动触发工作流**：
    - 进入 GitHub 仓库的 `Actions` 选项卡。
    - 选择你想运行的工作流。
    - 点击 `Run workflow` 按钮，选择分支，然后点击 `Run workflow` 以启动工作流。

#### 运行结果

##### 网页中查看

`Actions`栏 -> 点击最新的`Daily Check-in` workflow run -> `run_script` -> `Execute script`

可看到`Connect Info`：
（新号可能这里为空，多挂几天就有了）
![image](https://github.com/user-attachments/assets/853549a5-b11d-4d5a-9284-7ad2f8ea698b)

### 青龙面板使用

*注意：如果是docker容器创建的青龙，**请使用`whyour/qinglong:debian`镜像**，latest（alpine）版本可能无法安装部分依赖*

1. **依赖安装**
    - 安装Python依赖
      - 进入青龙面板 -> 依赖管理 -> 安装依赖
        - 依赖类型选择`python3`
        - 自动拆分选择`是`
        - 名称填写(仓库`requirements.txt`文件的完整内容)：
            ```
            scrapling[fetchers]>=0.4.1
            wcwidth==0.2.13
            tabulate==0.9.0
            loguru==0.7.2
            curl-cffi
            bs4
            ```
        - 点击确定
    - 安装 Scrapling 浏览器运行时
      - 安装完上述 Python 依赖后，在青龙容器 / 宿主机执行一次：
        ```bash
        scrapling install
        ```
      - 这是 Scrapling 首次运行前的必要步骤，用于准备浏览器运行时。


2. **添加仓库**
    - 进入青龙面板 -> 订阅管理 -> 创建订阅
    - 依次在对应的字段填入内容（未提及的不填）：
      - **名称**：Linux.DO 签到
      - **类型**：公开仓库
      - **链接**：https://github.com/doveppp/linuxdo-checkin.git
      - **分支**：main
      - **定时类型**：`crontab`
      - **定时规则**(拉取上游代码的时间，一天一次，可以自由调整频率): 0 0 * * *

3. **配置环境变量**
    - 进入青龙面板 -> 环境变量 -> 创建变量
    - 需要配置以下变量：
        - （二选一）`LINUXDO_COOKIES`：从浏览器复制的主站 Cookie 字符串（**推荐，优先使用**）
        - (可选) `LINUXDO_CONNECT_COOKIES`：从 `https://connect.linux.do` 复制的附加 Cookie 字符串，用于补充 Connect 域专属 Cookie
        - （二选一）`LINUXDO_USERNAME`：你的LinuxDo用户名/邮箱
        - （二选一）`LINUXDO_PASSWORD`：你的LinuxDo密码
        - (可选) `BROWSE_ENABLED`：是否启用浏览帖子功能，`true` 或 `false`，默认为 `true`
        - (可选) `LINUXDO_PROXY_URL`：代理地址，支持 `http://` / `https://` / 账号密码代理
        - (可选) `LINUXDO_PROXY_INSECURE`：设为 `true` 时，仅跳过连接上游 HTTPS 代理这一跳的证书校验
        - (可选) `GOTIFY_URL`：Gotify服务器地址
        - (可选) `GOTIFY_TOKEN`：Gotify应用Token
        - (可选) `SC3_PUSH_KEY`：Server酱³ SendKey
        - (可选) `WXPUSH_URL`：wxpush服务器地址
        - (可选) `WXPUSH_TOKEN`：wxpush的token
        - (可选) `TELEGRAM_BOT_TOKEN`：Telegram Bot Token
        - (可选) `TELEGRAM_CHAT_ID`：Telegram用户ID

4. **手动拉取脚本**
    - 首次添加仓库后不会立即拉取脚本，需要等待到定时任务触发，当然可以手动触发拉取
    - 点击右侧"运行"按钮可手动执行

#### 运行结果

##### 青龙面板中查看
- 进入青龙面板 -> 定时任务 -> 找到`Linux.DO 签到` -> 点击右侧的`日志`

### Gotify 通知

当配置了 `GOTIFY_URL` 和 `GOTIFY_TOKEN` 时，签到结果会通过 Gotify 推送通知。
具体 Gotify 配置方法请参考 [Gotify 官方文档](https://gotify.net/docs/).

### Server酱³ 通知

当配置了 `SC3_PUSH_KEY` 时，签到结果会通过 Server酱³ 推送通知。
获取 SendKey：请访问 [Server酱³ SendKey获取](https://sc3.ft07.com/sendkey) 获取你的推送密钥。

### wxpush 通知

当配置了 `WXPUSH_URL` 和 `WXPUSH_TOKEN` 时，签到结果会通过 wxpush 推送通知。
使用 POST 方式推送，请求地址为 `{WXPUSH_URL}/wxsend`。

### Telegram 通知

可选功能：配置 Telegram 通知，实时获取签到结果。

需要在 GitHub Secrets 中配置：
- `TELEGRAM_BOT_TOKEN`：Telegram Bot Token
- `TELEGRAM_CHAT_ID`：Telegram 用户 ID

获取方法：
1. Bot Token：与 [@BotFather](https://t.me/BotFather) 对话创建机器人获取
2. 用户 ID：与 [@userinfobot](https://t.me/userinfobot) 对话获取

未配置时将自动跳过通知功能，不影响签到。


## 自动更新

- **Github Actions**：默认状态下自动更新是关闭的，[点击此处](https://github.com/ChatGPTNextWeb/ChatGPT-Next-Web/blob/main/README_CN.md#%E6%89%93%E5%BC%80%E8%87%AA%E5%8A%A8%E6%9B%B4%E6%96%B0)
查看打开自动更新步骤。
- **青龙面板**：更新是以仓库设置的定时规则有关，按照本文配置，则是每天0点更新一次。

