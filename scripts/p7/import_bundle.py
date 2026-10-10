#!/usr/bin/env python3
"""导入 B3 交付包；只登记和封存，独立审批与激活必须在脚本外完成。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
import rfc8785


class ImportFailure(RuntimeError):
    """服务端拒绝、返回契约不符或本地状态不完整时立即中止。"""


class NoRedirect(HTTPRedirectHandler):
    """写 API 的重定向同样视为失败，避免改方法或向新地址转发会话凭据。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ImportFailure("导入清单必须是 JSON 对象")
    return value


def save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        temporary = Path(stream.name)
    os.replace(temporary, path)


class Api:
    def __init__(self, base_url: str, cookie: str | None, csrf_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.cookie = cookie
        self.csrf_token = csrf_token
        self.opener = build_opener(NoRedirect())

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, revision: int | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body is not None:
            headers.update({"Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())})
            if self.csrf_token:
                headers["X-CSRF-TOKEN"] = self.csrf_token
        if revision is not None:
            headers["If-Match"] = str(revision)
        request = Request(self.base_url + path, data=canonical(body) if body is not None else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                if not 200 <= response.status < 300:
                    raise ImportFailure(f"{method} {path}: HTTP {response.status}")
                envelope = json.loads(response.read().decode())
        except HTTPError as exc:
            exc.close()
            raise ImportFailure(f"{method} {path}: HTTP {exc.code}") from exc
        except URLError as exc:
            raise ImportFailure(f"{method} {path}: 网络请求失败") from exc
        data = envelope.get("data") if isinstance(envelope, dict) else None
        if not isinstance(envelope, dict) or envelope.get("error") is not None or not isinstance(data, dict):
            raise ImportFailure(f"{method} {path}: 响应没有成功 data 对象")
        return data


def replace(value: Any, state: dict[str, Any]) -> Any:
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        name = value[2:-1]
        if name not in state:
            raise ImportFailure(f"导入清单引用了尚未产生的 {name}")
        return state[name]
    if isinstance(value, list):
        return [replace(item, state) for item in value]
    if isinstance(value, dict):
        return {key: replace(item, state) for key, item in value.items()}
    return value


def require(data: dict[str, Any], **expected: Any) -> None:
    for key, value in expected.items():
        if data.get(key) != value:
            raise ImportFailure(f"返回字段 {key} 不符合预期")


def post(api: Api, state: dict[str, Any], path: str, body: dict[str, Any], checks: dict[str, Any], state_key: str, state_path: Path) -> dict[str, Any]:
    result = api.request("POST", path, replace(body, state))
    identifier = result.get("id")
    if not isinstance(identifier, str):
        raise ImportFailure(f"{path} 未返回 id")
    state[state_key] = identifier
    save(state_path, state)
    require(result, **checks)
    return result


def capability_refs(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """清单只能选择新建单条能力或显式复用列表；复用绑定不可变 payload 摘要。"""
    if ("capability" in plan) == ("existingCapabilities" in plan):
        raise ImportFailure("必须且只能提供 capability 或 existingCapabilities")
    if "capability" in plan:
        if not isinstance(plan["capability"], dict):
            raise ImportFailure("capability 必须是对象")
        return []
    refs = plan["existingCapabilities"]
    if not isinstance(refs, list) or not refs:
        raise ImportFailure("existingCapabilities 必须是非空列表")
    identifiers = set()
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"id", "payload", "payloadSha256"}:
            raise ImportFailure("既有能力须提供 id、payload 和 payloadSha256")
        identifier = ref["id"]
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier or identifier in identifiers:
            raise ImportFailure("既有能力 UUID 无效或重复")
        identifiers.add(identifier)
        if not isinstance(ref["payload"], dict) or sha256(ref["payload"]) != ref["payloadSha256"]:
            raise ImportFailure("既有能力 payload 摘要不一致")
    return refs


def verify_capability(api: Api, ref: dict[str, Any]) -> None:
    """回读身份、级别、范围与全部签名证据字段，不降级或补造缺失能力。"""
    payload = ref["payload"]
    registered = api.request("GET", f"/capabilities/{ref['id']}")
    require(registered, id=ref["id"], payload=payload, level=payload["level"],
            scope=payload.get("scope", "peer_service"))
    if sha256(registered["payload"]) != ref["payloadSha256"]:
        raise ImportFailure("既有能力回读摘要不一致")


def require_capability_ids(body: dict[str, Any], field: str, identifiers: list[str]) -> None:
    value = body.get(field)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value) or sorted(value) != identifiers:
        raise ImportFailure("策略和发布组合必须绑定本次核验的完整能力集合")


def prepare(api: Api, plan: dict[str, Any], state_path: Path) -> None:
    if state_path.exists():
        raise ImportFailure("状态文件已存在，拒绝覆盖；请核查原导入记录")
    refs = capability_refs(plan)
    for ref in refs:
        verify_capability(api, ref)
    state: dict[str, Any] = {"version": 1, "phase": "prepare", "plan": plan}
    save(state_path, state)
    model = post(api, state, "/models", plan["model"], {"candidateOnly": True, "validationStatus": "pending"}, "modelId", state_path)
    registered_model = api.request("GET", f"/models/{state['modelId']}")
    require(registered_model, id=state["modelId"], manifestSha256=plan["model"]["manifestSha256"], validationStatus="pending")
    manifest = registered_model["manifest"]
    require(manifest, modelId=state["modelId"], artifactSha256=registered_model["artifactSha256"])
    state["manifest"] = manifest
    validation = api.request("POST", f"/models/{model['id']}/validations", replace(plan["validation"], state))
    require(validation, status="validated", artifactSha256=manifest["artifactSha256"])
    evaluation = post(api, state, "/evaluation-plans", plan["evaluationPlan"], {}, "evaluationPlanId", state_path)
    expected_plan_hash = sha256(replace(plan["evaluationPlan"], state))
    require(evaluation, planSha256=expected_plan_hash)
    require(manifest, evaluationPlanSha256=expected_plan_hash)
    state["evaluationPlanSha256"] = expected_plan_hash
    if not refs:
        payload = replace(plan["capability"], state)
        capability = post(api, state, "/capabilities", payload, {"level": payload["level"], "scope": payload.get("scope", "peer_service")}, "capabilityId", state_path)
        refs = [{"id": capability["id"], "payload": payload, "payloadSha256": sha256(payload)}]
        verify_capability(api, refs[0])
    state["capabilityIds"] = sorted(ref["id"] for ref in refs)
    state["capabilityBindings"] = refs
    if len(refs) == 1:
        state["capabilityId"] = refs[0]["id"]
    save(state_path, state)
    require_capability_ids(replace(plan["decisionPolicy"], state), "supportedCapabilityIds", state["capabilityIds"])
    require_capability_ids({"capabilityIds": replace(plan["releaseBundle"].get("capabilityIds"), state)}, "capabilityIds", state["capabilityIds"])
    policy = post(api, state, "/decision-policies", plan["decisionPolicy"], {"status": "draft", "revision": 1}, "policyId", state_path)
    state.update({"phase": "awaiting-policy-review", "policyRevision": policy["revision"], "policySha256": sha256(replace(plan["decisionPolicy"], state)), "plan": plan})
    require(api.request("GET", f"/decision-policies/{state['policyId']}"), id=state["policyId"], status="draft", definitionSha256=state["policySha256"])
    save(state_path, state)
    print(f"已停在独立策略审查：POST /decision-policies/{policy['id']}/reviews。脚本不会调用此接口。", file=sys.stderr)


def resume(api: Api, state_path: Path, reports: dict[str, Any] | None = None) -> None:
    state = load(state_path)
    if state.get("phase") != "awaiting-policy-review":
        raise ImportFailure("状态文件不在等待策略独立审查阶段")
    plan = state.get("plan")
    if not isinstance(plan, dict):
        raise ImportFailure("状态文件缺少原始导入清单")
    policy = api.request("GET", f"/decision-policies/{state['policyId']}")
    require(policy, id=state["policyId"], status="reviewed", definitionSha256=state["policySha256"], modelId=state["modelId"])
    if sha256(replace(plan["decisionPolicy"], state)) != state["policySha256"]:
        raise ImportFailure("恢复清单策略摘要不一致")
    refs = capability_refs(plan)
    if not refs:
        payload = replace(plan["capability"], state)
        refs = [{"id": state["capabilityId"], "payload": payload, "payloadSha256": sha256(payload)}]
    identifiers = sorted(ref["id"] for ref in refs)
    if state.get("capabilityBindings", refs) != refs or state.get("capabilityIds", identifiers) != identifiers:
        raise ImportFailure("恢复清单能力绑定不一致")
    for ref in refs:
        verify_capability(api, ref)
    require_capability_ids(replace(plan["decisionPolicy"], state), "supportedCapabilityIds", identifiers)
    require_capability_ids(replace(plan["releaseBundle"], state), "capabilityIds", identifiers)
    # 首阶段产生能力 UUID；外部 runner 据此签发同 subject 报告后，显式提供报告引用。
    imports = reports["imports"] if reports is not None else plan["imports"]
    if not isinstance(imports, list) or not imports:
        raise ImportFailure("封存前必须提供非空报告清单")
    manifest = state["manifest"]
    body = replace(plan["releaseBundle"], state)
    subject = {"contractVersion": manifest["contractVersion"], "protocolVersions": body["protocolVersions"],
               "modelId": state["modelId"], "manifestSha256": plan["model"]["manifestSha256"],
               "policyId": state["policyId"], "policySha256": state["policySha256"],
               "featureProfileSha256": body["featureProfileSha256"], "extractorSha256": body["extractorSha256"],
               "evaluationPlanSha256": state["evaluationPlanSha256"], "capabilityIds": sorted(body["capabilityIds"]),
               "environment": body["environment"]}
    state.update({"phase": "importing-reports", "imports": imports})
    save(state_path, state)
    bundle = post(api, state, "/release-bundles", plan["releaseBundle"], {"status": "candidate", "revision": 1}, "bundleId", state_path)
    require(bundle, subjectSha256=sha256(subject))
    report_bindings = []
    for index, report in enumerate(imports):
        imported = post(api, state, f"/release-bundles/{bundle['id']}/imports", report, {"status": "passed"}, f"evaluationId{index}", state_path)
        report_body = replace(report, state)
        require(api.request("GET", f"/evaluations/{imported['id']}"), id=imported["id"], status="passed", bundleId=bundle["id"], reportSha256=report_body["sha256"])
        report_bindings.append({"evaluationId": imported["id"], "reportSha256": report_body["sha256"]})
    sealing = replace(plan["sealing"], state)
    sealing["evaluationIds"] = [state[f"evaluationId{index}"] for index in range(len(imports))]
    sealed = api.request("POST", f"/release-bundles/{bundle['id']}/sealings", sealing, revision=bundle["revision"])
    sealed_hash = sha256({"subjectSha256": bundle["subjectSha256"], "reports": sorted(report_bindings, key=lambda r: r["evaluationId"])})
    require(sealed, id=bundle["id"], status="evaluated", revision=bundle["revision"] + 1, sealedManifestSha256=sealed_hash)
    state.update({"phase": "awaiting-bundle-decision", "bundleRevision": sealed.get("revision"), "sealedManifestSha256": sealed.get("sealedManifestSha256")})
    save(state_path, state)
    print(f"已停在独立发布包决策：POST /release-bundles/{bundle['id']}/decisions。脚本不会审批或激活。", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--cookie-file", type=Path, help="仅保存会话 Cookie 的私有文件；不从命令行接收凭据")
    parser.add_argument("--csrf-file", type=Path, help="同一会话的 CSRF token 私有文件")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", type=Path, help="首次导入清单")
    group.add_argument("--resume-state", type=Path, help="独立策略审查后的状态文件")
    parser.add_argument("--state", type=Path, help="首次导入写出的非敏感状态文件")
    parser.add_argument("--reports", type=Path, help="恢复时读取外部签发报告的 imports 清单；不生成或签发报告")
    args = parser.parse_args()
    try:
        cookie = args.cookie_file.read_text(encoding="utf-8").strip() if args.cookie_file else None
        csrf_token = args.csrf_file.read_text(encoding="utf-8").strip() if args.csrf_file else None
        api = Api(args.base_url, cookie, csrf_token)
        if args.plan:
            if not args.state:
                parser.error("--plan 必须同时提供 --state")
            if args.reports:
                parser.error("--reports 只能用于 --resume-state")
            prepare(api, load(args.plan), args.state)
        else:
            resume(api, args.resume_state, load(args.reports) if args.reports else None)
    except (ImportFailure, KeyError, TypeError, ValueError, OSError) as exc:
        print(f"导入失败：{exc if isinstance(exc, ImportFailure) else type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
