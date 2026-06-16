import re

from core.config import settings

# ---------------------------------------------------------------------------
# 配置常量（从 .env 读取，未设置时使用默认值）
# ---------------------------------------------------------------------------

_MAX_REQUESTS_PER_SECOND = settings.FW_MAX_REQUESTS_PER_SECOND
_BAN_THRESHOLD = settings.FW_BAN_THRESHOLD
_BAN_DURATION = settings.FW_BAN_DURATION  # 秒

# Redis key 前缀
_KEY_RATE = "fw:rate:"
_KEY_VIOL = "fw:viol:"
_KEY_BAN = "fw:ban:"

# ---------------------------------------------------------------------------
# 爬虫检测
# ---------------------------------------------------------------------------
_CRAWLER_UA_PATTERNS = re.compile(
    r"(bot|crawler|spider|scraper|curl|wget|python-requests|go-http-client"
    r"|java/|httpclient|axios|node-fetch|libwww|mechanize|scrapy|okhttp"
    r"|headlesschrome|phantomjs|selenium|puppeteer|playwright)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 攻击检测模式：XSS / SQL注入 / 路径穿越 / 命令注入 / SSRF
# 以下正则表达式用于检测常见的Web攻击特征
# ---------------------------------------------------------------------------

# XSS 攻击检测：脚本标签、事件处理器、危险 JavaScript API
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

# SQL 注入检测：SQL关键字组合、注释符、时间盲注、文件操作等
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

# 路径穿越检测：目录遍历符号及各种编码变体、敏感系统文件访问
_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\)"
    r"|(%2e%2e[%2f%5c])"
    r"|(%252e%252e%252f)"
    r"|(\.\.%c0%af|\.\.%c1%9c)"
    r"|(/etc/(passwd|shadow|hosts|group))"
    r"|(/(proc|sys)/)"
    r"|(\\windows\\|\\system32\\|\\boot\.ini)"
    r"|(/\.env|/\.git/|/\.ssh/)",
    re.IGNORECASE,
)

# 命令注入检测：Shell元字符、命令分隔符、子命令执行、危险函数
_CMDI_PATTERNS = re.compile(
    r"(;\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)\b)"
    r"|(\|\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)\b)"
    r"|(`[^`]*`)"
    r"|(\$\([^)]+\))"
    r"|(\$\{[^}]*\})"
    r"|(\b(eval|exec|system|passthru|popen|proc_open|shell_exec)\s*\()"
    r"|(\|{2}\s*(rm|cat|wget|curl)\b)"
    r"|(&{2}\s*(rm|cat|wget|curl)\b)"
    r"|(\b(chmod|chown|chgrp|mkfs|dd|fdisk)\s)"
    r"|(/bin/(sh|bash|dash|zsh|csh)\b)"
    r"|(\\x[0-9a-f]{2}.*\\x[0-9a-f]{2})",
    re.IGNORECASE,
)

# SSRF 检测：内网IP、本地回环、云厂商元数据端点、危险协议
_SSRF_PATTERNS = re.compile(
    r"(https?://(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))"
    r"|(https?://0x[0-9a-f]+)"
    r"|(https?://0[0-7]+\.)"
    r"|(https?://localhost)"
    r"|(https?://\[::1?\])"
    r"|(https?://metadata\.google)"
    r"|(https?://169\.254\.169\.254)"
    r"|(https?://100\.100\.100\.200)"
    r"|(\bgopher://|\bdict://|\bfile://|\bftp://)",
    re.IGNORECASE,
)

# 需要额外检查的请求头列表
_INSPECTED_HEADERS = [
    "Referer",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Origin",
]
