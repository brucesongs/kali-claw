#!/usr/bin/env python3
"""
Chronicle Detailed Record Template Generator
Usage: python3 chronicle-template.py <event_name> <event_type>
"""

import sys
import os
from datetime import datetime

# Event type mapping
EVENT_TYPES = {
    "launch": "🚀 Project Launch",
    "milestone": "🎉 Milestone Reached",
    "learning": "📚 Learning Completed",
    "config": "🔧 Environment Configuration",
    "security": "🔴 Security Finding",
    "report": "📄 Report Output",
    "optimize": "⚙️ System Optimization",
    "goal": "🎯 Goal Setting"
}

def create_template(event_name, event_type_key):
    """Generate chronicle detailed record template"""

    # Get event type
    event_type = EVENT_TYPES.get(event_type_key, "📌 Other Event")

    # Generate date
    today = datetime.now()
    date_str = today.strftime("%Y-%m-%d")
    datetime_str = today.strftime("%Y-%m-%d %H:%M")

    # Generate filename (replace spaces with hyphens)
    filename_event = event_name.replace(" ", "-").lower()
    filename = f"chronicle/{date_str[:7]}/{date_str}-{filename_event}.md"

    # Generate template
    template = f"""# {date_str} - {event_name}

> **Event Type**: {event_type}
> **Record Date**: {datetime_str}

---

## 📋 Event Summary

**One-line Summary**: [To be filled in]

**Key Outcomes**:
- ✅ [To be filled in]
- ✅ [To be filled in]
- ✅ [To be filled in]

---

## 🎯 Background & Goals

### Background
[Why did this happen? What is the context?]

### Goals
[What goals were intended to be achieved?]

---

## 🚀 Execution Process

### Phase 1: [Phase Name]
- **Time**: HH:MM - HH:MM
- **Action**: [What was done]
- **Result**: [What was the outcome]

### Phase 2: [Phase Name]
- **Time**: HH:MM - HH:MM
- **Action**: [What was done]
- **Result**: [What was the outcome]

---

## 💡 Key Conversation Excerpts

**User Instructions**:
> "[Original instruction content]"

**Assistant Response**:
> "[Key response content]"

---

## 📊 Outcomes & Deliverables

### Output Files
- `path/to/file1.md` - [Description]
- `path/to/file2.py` - [Description]
- `path/to/file3.sh` - [Description]

### Quantitative Results
| Metric | Value | Description |
|--------|-------|-------------|
| Metric 1 | XXX | Description |
| Metric 2 | XXX | Description |
| Metric 3 | XXX | Description |

---

## 🔄 Follow-up Impact

### Impact on the Project
[What impact did this have on the current project?]

### Impact on Capabilities
[What capabilities were enhanced?]

### Impact on the Future
[What long-term impact does this have?]

---

## 📚 Related Links

- **Detailed Notes**: `memory/{date_str}.md`
- **Knowledge Distillation**: `MEMORY.md#[section]`
- **Related Reports**: `docs/reports/xxx.md`
- **Tool Output**: `tools/xxx.py`

---

## 📝 Additional Notes

[Any other content to record]

---

**Recorded by**: SecMind
**Record Time**: {datetime_str}
**Last Updated**: {datetime_str}
"""

    return filename, template

def main():
    """Main function"""

    # Check arguments
    if len(sys.argv) < 3:
        print("=" * 60)
        print("Chronicle Detailed Record Template Generator")
        print("=" * 60)
        print("\nUsage: python3 chronicle-template.py <event_name> <event_type>")
        print("\nEvent Types:")
        for key, value in EVENT_TYPES.items():
            print(f"  {key:12} - {value}")
        print("\nExamples:")
        print('  python3 chronicle-template.py "SQLi-Labs-Completed" milestone')
        print('  python3 chronicle-template.py "Go-Toolchain-Setup" config')
        print("=" * 60)
        sys.exit(1)

    # Get arguments
    event_name = sys.argv[1]
    event_type = sys.argv[2]

    # Validate event type
    if event_type not in EVENT_TYPES:
        print(f"❌ Error: Unknown event type '{event_type}'")
        print(f"Available types: {', '.join(EVENT_TYPES.keys())}")
        sys.exit(1)

    # Generate template
    filename, template = create_template(event_name, event_type)

    # Create directory
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Write file
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(template)

    print("=" * 60)
    print("✅ Chronicle Detailed Record Template Generated")
    print("=" * 60)
    print(f"File Location: {filename}")
    print(f"Event Type: {EVENT_TYPES[event_type]}")
    print(f"Event Name: {event_name}")
    print("\nNext Steps:")
    print("1. Edit the file and fill in the details")
    print("2. Update CHRONICLE.md to add an index entry")
    print("3. (Optional) Update MEMORY.md to distill key knowledge")
    print("=" * 60)

if __name__ == "__main__":
    main()
