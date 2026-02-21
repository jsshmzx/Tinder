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
    r"|on\w+\s*=\s*[\"']|<\s*iframe|<\s*object|<\s*embed|<\s*link"
    r"|<\s*img[^>]+onerror|document\s*\.\s*cookie|eval\s*\(|expression\s*\()",
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
    r"|\/\*[\s\S]*?\*\/)",
    re.IGNORECASE,
)
