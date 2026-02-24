import re

# ---------------------------------------------------------------------------
# 配置常量
# ---------------------------------------------------------------------------

# 每秒最大请求次数（超过则视为高频攻击）
_MAX_REQUESTS_PER_SECOND = 20

# IP 违规次数上限（达到后封禁）
_BAN_THRESHOLD = 10

# IP 封禁时长（秒）：24 小时
_BAN_DURATION = 86400

# Redis key 前缀
_KEY_RATE = "fw:rate:"       # 速率计数  fw:rate:<ip> -> count (TTL 1s)
_KEY_VIOL = "fw:viol:"       # 违规计数  fw:viol:<ip> -> count (TTL 24h)
_KEY_BAN = "fw:ban:"         # 封禁标记  fw:ban:<ip>  -> "1"  (TTL 24h)

# ---------------------------------------------------------------------------
# 常见爬虫 User-Agent 关键词（不区分大小写）
# ---------------------------------------------------------------------------
_CRAWLER_UA_PATTERNS = re.compile(
    r"(bot|crawler|spider|scraper|curl|wget|python-requests|go-http-client"
    r"|java/|httpclient|axios|node-fetch|libwww|mechanize|scrapy|okhttp"
    r"|headlesschrome|phantomjs|selenium|puppeteer|playwright)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# XSS 检测模式
# ---------------------------------------------------------------------------
_XSS_PATTERNS = re.compile(
    r"(<\s*script[\s\S]*?>|<\s*/\s*script\s*>|javascript\s*:|vbscript\s*:"
    r"|data\s*:\s*text/html"
    r"|on\w+\s*=\s*[\"'\s]"
    r"|<\s*iframe|<\s*object|<\s*embed|<\s*link"
    r"|<\s*img[^>]+onerror|<\s*svg[^>]*\bon\w+\s*="
    r"|<\s*math|<\s*details[^>]*\bontoggle"
    r"|<\s*body[^>]+onload"
    r"|document\s*\.\s*(cookie|domain|write|location)"
    r"|window\s*\.\s*(location|open)"
    r"|eval\s*\(|expression\s*\("
    r"|String\s*\.\s*fromCharCode"
    r"|atob\s*\(|decodeURIComponent\s*\("
    r"|\.innerHTML\s*=|\.outerHTML\s*="
    r"|<\s*marquee|<\s*isindex|<\s*form[^>]*\baction\s*="
    r"|<\s*input[^>]*\bonfocus"
    r"|<\s*textarea|<\s*keygen|<\s*video[^>]*\bonerror"
    r"|<\s*audio[^>]*\bonerror"
    r"|prompt\s*\(|confirm\s*\(|alert\s*\()",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SQL 注入检测模式
# ---------------------------------------------------------------------------
_SQLI_PATTERNS = re.compile(
    r"(\b(select|insert|update|delete|drop|truncate|alter|create|replace"
    r"|union|exec|execute|xp_|sp_)\b.*\b(from|into|table|where|set)\b"
    r"|'[\s\S]*?--"
    r"|;\s*(drop|delete|update|insert|select)"
    r"|\bor\b\s+[\w'\"]+\s*=\s*[\w'\"]+"
    r"|\band\b\s+[\w'\"]+\s*=\s*[\w'\"]+"
    r"|\/\*[\s\S]*?\*\/"
    r"|\bunion\s+all\s+select\b"
    r"|\bselect\s+@@"
    r"|\bsleep\s*\(\s*\d"
    r"|\bbenchmark\s*\("
    r"|\bwaitfor\s+delay\b"
    r"|\bload_file\s*\("
    r"|\binto\s+(out|dump)file\b"
    r"|\bconcat\s*\(|group_concat\s*\("
    r"|\bchar\s*\(\s*\d"
    r"|\bhaving\b\s+\d+\s*="
    r"|\border\s+by\s+\d+\s*--"
    r"|0x[0-9a-f]{6,}"
    r"|\binformation_schema\b"
    r"|\bpg_sleep\b|\bdbms_pipe\b"
    r"|\butl_http\b|\bsys\.)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 路径穿越检测模式
# ---------------------------------------------------------------------------
_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\)"                      # ../ 或 ..\
    r"|(%2e%2e[%2f%5c])"                   # URL 编码的 ../
    r"|(%252e%252e%252f)"                  # 双重 URL 编码
    r"|(\.\.%c0%af|\.\.%c1%9c)"            # UTF-8 过长编码绕过
    r"|(/etc/(passwd|shadow|hosts|group))"  # Linux 敏感文件
    r"|(/(proc|sys)/)"                     # Linux 伪文件系统
    r"|(\\windows\\|\\system32\\|\\boot\.ini)"  # Windows 敏感路径
    r"|(/\.env|/\.git/|/\.ssh/)",          # 配置文件泄露
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 命令注入检测模式
# ---------------------------------------------------------------------------
_CMDI_PATTERNS = re.compile(
    r"(;\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)\b)"
    r"|(\|\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)\b)"
    r"|(`[^`]*`)"                          # 反引号命令执行
    r"|(\$\([^)]+\))"                      # $() 子命令
    r"|(\$\{[^}]*\})"                      # ${} 变量注入
    r"|(\b(eval|exec|system|passthru|popen|proc_open|shell_exec)\s*\()"
    r"|(\|{2}\s*(rm|cat|wget|curl)\b)"     # || 链式命令
    r"|(&{2}\s*(rm|cat|wget|curl)\b)"      # && 链式命令
    r"|(\b(chmod|chown|chgrp|mkfs|dd|fdisk)\s)"
    r"|(/bin/(sh|bash|dash|zsh|csh)\b)"
    r"|(\\x[0-9a-f]{2}.*\\x[0-9a-f]{2})", # Hex 编码的 shell payload
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SSRF 检测模式
# ---------------------------------------------------------------------------
_SSRF_PATTERNS = re.compile(
    r"(https?://(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))"
    r"|(https?://0x[0-9a-f]+)"            # 十六进制 IP
    r"|(https?://0[0-7]+\.)"              # 八进制 IP
    r"|(https?://localhost)"
    r"|(https?://\[::1?\])"               # IPv6 回环
    r"|(https?://metadata\.google)"       # 云厂商元数据服务
    r"|(https?://169\.254\.169\.254)"     # AWS/GCP 元数据端点
    r"|(https?://100\.100\.100\.200)"     # 阿里云元数据端点
    r"|(\bgopher://|\bdict://|\bfile://|\bftp://)", # 危险协议
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 需要额外检查的请求头列表
# ---------------------------------------------------------------------------
_INSPECTED_HEADERS = [
    "Referer",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Origin",
]
