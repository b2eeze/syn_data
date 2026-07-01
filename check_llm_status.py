#!/usr/bin/env python3
"""检查 LLM API 状态（欠费/限流/正常），输出到本地文件"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

OUTPUT_FILE = Path(__file__).parent / "llm_status.json"

STATUS_MAP = {
    "Arrearage": "欠费停服",
    "limit_burst_rate": "突发限流",
    "insufficient_quota": "配额耗尽",
    "200": "正常可用",
}


def check() -> dict:
    base_url = os.environ.get("LLM_BASE_URL", "")
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "")

    if not all([base_url, api_key, model]):
        return {
            "timestamp": datetime.now().isoformat(),
            "status": "配置缺失",
            "detail": f"base_url={'set' if base_url else 'missing'}, "
                      f"api_key={'set' if api_key else 'missing'}, "
                      f"model={'set' if model else 'missing'}",
        }

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "回复OK"}],
        "max_tokens": 5,
    }

    try:
        session = requests.Session()
        session.trust_env = False
        r = session.post(url, headers=headers, json=payload, timeout=10)
        body = r.json() if r.text else {}

        if r.status_code == 200:
            status = "正常可用"
            detail = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        else:
            error = body.get("error", {})
            code = error.get("code", str(r.status_code))
            message = error.get("message", "")
            status = STATUS_MAP.get(code, f"未知错误 ({code})")
            detail = message[:300]
    except Exception as e:
        status = "连接失败"
        detail = str(e)[:300]

    result = {
        "timestamp": datetime.now().isoformat(),
        "status": status,
        "detail": detail,
    }
    return result


def main():
    result = check()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 返回码：0=正常，1=异常
    if result["status"] == "正常可用":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
