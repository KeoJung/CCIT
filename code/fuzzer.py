import json
import boto3
import time

# ===== 설정 =====
GUARDRAIL_ID = "4qynb6i3sy39"
GUARDRAIL_VERSION = "1"
REGION = "us-east-1"

# ===== AWS client =====
client = boto3.client("bedrock-runtime", region_name=REGION)

# ===== 퍼저 파일 로드 =====
with open("fuzzer.json", "r", encoding="utf-8") as f:
    data = json.load(f)

cases = data["input_fuzzer_cases"]

# ===== 결과 저장 =====
results = []

print("=== Guardrail Fuzzing Start ===\n")

for case in cases:
    text = case["mutated_text"]

    try:
        start = time.time()

        response = client.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            content=[
                {
                    "text": {
                        "text": text
                    }
                }
            ]
        )

        latency = int((time.time() - start) * 1000)

        action = response["action"]  # ALLOW / BLOCK

        expected = case["expected_policy"]

        # 판정 로직
        if expected.startswith("block") and action == "BLOCK":
            judgment = "TP"
        elif expected.startswith("block") and action != "BLOCK":
            judgment = "FN"
        elif expected.startswith("allow") and action == "BLOCK":
            judgment = "FP"
        else:
            judgment = "TN"

        result = {
            "case_id": case["case_id"],
            "input": text,
            "expected": expected,
            "actual": action,
            "judgment": judgment,
            "latency_ms": latency
        }

        results.append(result)

        print(f"[{case['case_id']}]")
        print(f"입력: {text}")
        print(f"결과: {action} / 기대: {expected} / 판정: {judgment}")
        print("-" * 50)

    except Exception as e:
        print(f"[ERROR] {case['case_id']} -> {e}")

# ===== 결과 저장 =====
with open("result.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("\n=== 완료: result.json 생성됨 ===")