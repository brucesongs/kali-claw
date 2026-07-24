#!/usr/bin/env python3
"""
生成完整 1508 实例的 cybergym-full-1508.json

输入: mask_map.json (所有 1508 个实例的 ID 映射)
输出: docs/cybergym-full-1508.json (JSON 格式的实例清单)

使用方法:
  python3 validation/gen-full-instance-list.py \
    --mask-map /path/to/mask_map.json \
    --output docs/cybergym-full-1508.json
"""

import json
import argparse
from pathlib import Path
from datetime import datetime


def generate_instance_list(mask_map_path: Path, output_path: Path):
    """从 mask_map.json 生成完整 1508 实例的测试清单"""

    # 读取 mask_map.json
    with open(mask_map_path) as f:
        mask_map = json.load(f)

    print(f"读取 {len(mask_map)} 个实例 ID from {mask_map_path}")

    # 分离 arvo 和 oss-fuzz 实例
    arvo_instances = sorted(
        [(k, v) for k, v in mask_map.items() if k.startswith("arvo:")],
        key=lambda x: int(x[0].split(":")[1])
    )
    oss_fuzz_instances = sorted(
        [(k, v) for k, v in mask_map.items() if k.startswith("oss-fuzz:")],
        key=lambda x: int(x[0].split(":")[1])
    )

    print(f"  arvo 类型: {len(arvo_instances)} 个")
    print(f"  oss-fuzz 类型: {len(oss_fuzz_instances)} 个")

    # 生成实例列表
    instances = []
    kali_claw_id_counter = 1

    for instance_id, _ in arvo_instances + oss_fuzz_instances:
        kali_claw_id = f"FULL{kali_claw_id_counter:04d}"

        instances.append({
            "kali_claw_id": kali_claw_id,
            "cybergym_instance_id": instance_id,
            "difficulty": "level1",
            "bug_class": "unknown",
            "project": f"cybergym-{instance_id}",
            "local_data_available": False,
            "notes": f"auto-generated from mask_map.json, position {kali_claw_id_counter}/1508"
        })

        kali_claw_id_counter += 1

    # 构建输出 JSON
    output_data = {
        "calibration_id": "v0.1.47.1-full",
        "description": "完整 CyberGym 1508 实例顺序测试（arvo + oss-fuzz）",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total": len(instances),
        "arvo_count": len(arvo_instances),
        "oss_fuzz_count": len(oss_fuzz_instances),
        "notes": "arvo 实例优先测试，oss-fuzz 类型可跳过以加快调度（单独处理）",
        "instances": instances
    }

    # 写入输出文件
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n✓ 生成完成: {output_path}")
    print(f"  总实例数: {output_data['total']}")
    print(f"  arvo: {output_data['arvo_count']}")
    print(f"  oss-fuzz: {output_data['oss_fuzz_count']}")

    # 显示前 5 个和后 5 个实例
    print(f"\n前 5 个实例:")
    for inst in instances[:5]:
        print(f"  {inst['kali_claw_id']}: {inst['cybergym_instance_id']}")

    print(f"\n最后 5 个实例:")
    for inst in instances[-5:]:
        print(f"  {inst['kali_claw_id']}: {inst['cybergym_instance_id']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="生成完整 1508 实例的 JSON 清单")
    parser.add_argument(
        "--mask-map",
        type=Path,
        required=True,
        help="mask_map.json 文件路径"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/cybergym-full-1508.json"),
        help="输出 JSON 文件路径（默认: docs/cybergym-full-1508.json）"
    )

    args = parser.parse_args()

    if not args.mask_map.exists():
        print(f"✗ 错误: mask_map 文件不存在: {args.mask_map}")
        exit(1)

    generate_instance_list(args.mask_map, args.output)
