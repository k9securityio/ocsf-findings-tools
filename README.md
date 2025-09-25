# OCSF Security Findings Tools

This repository contains simple command-line tools to work with security findings in the Open Cybersecurity Framework (
OCSF) format.

## Export OCSF Findings from AWS Security Hub

You can export findings from AWS Security Hub in OCSF format using
the [export_ocsf_findings_security_hub.py](export_ocsf_findings_security_hub.py) tool. By default, the tool exports all
findings. Use the flexible filtering options below to narrow your results to what you need.

### Command-Line Options

-v, --verbose

Enable verbose output to stderr, including filters and pagination progress.

- Usage: -v or --verbose
- Shows: Applied filters in JSON format, pagination progress, total findings count
- Multiple values: No

--account ACCOUNT

Filter findings by AWS account ID.

- Usage: --account 123456789012
- Multiple values: No

--status STATUS

Filter findings by status. Specify multiple times for OR logic.

- Usage: --status New --status "In Progress"
- Valid values: New, In Progress, On Hold, Suppressed, Resolved, Archived, Deleted, Unknown, Other
- Multiple values: Yes (OR logic)

--severity SEVERITY

Filter findings by severity level. Specify multiple times for OR logic.

- Usage: --severity Critical --severity High
- Valid values: Fatal, Critical, High, Medium, Low, Informational, Unknown, Other
- Multiple values: Yes (OR logic)

--created-days-ago N

Filter findings created within the last N days.

- Usage: --created-days-ago 30
- Multiple values: No

--activity-name ACTIVITY

Filter findings by activity name. Specify multiple times for OR logic.

- Usage: --activity-name Create --activity-name Update
- Valid values: Create, Update, Close, Unknown, Other
- Multiple values: Yes (OR logic)

--activity-name-not ACTIVITY

_Exclude_ findings with specific activity names. Specify multiple times to exclude
multiple activities.

- Usage: --activity-name-not Close --activity-name-not Update
- Valid values: Create, Update, Close, Unknown, Other
- Multiple values: Yes (AND logic - excludes all specified values)

Filter Logic

- Multiple values within same filter: OR logic (except for --activity-name-not)
- Different filter types: AND logic
- Exclusion filters (--activity-name-not): AND logic (must not match ANY specified
  value)

### Common Use Cases

Export Security Hub Default Posture Management View

```shell
./export_ocsf_findings_security_hub.py \
--status New \
--status "In Progress" \
--activity-name-not Close
```

With verbose output:

```shell
./export_ocsf_findings_security_hub.py \
--status New \
--status "In Progress" \
--activity-name-not Close \
--verbose
```

Export Recent High-Priority Findings

```shell
./export_ocsf_findings_security_hub.py \
--severity Fatal \
--severity Critical \
--severity High \
--created-days-ago 7
```

Export Active Findings for a Specific Account

```shell
./export_ocsf_findings_security_hub.py \
--account 123456789012 \
--status New \
--activity-name Create \
--activity-name Update

```

Export All Findings (No Filters)

```shell
./export_ocsf_findings_security_hub.py > all-findings.json
```

### Output

The script outputs findings in OCSF-compliant JSON format to stdout. Redirect to a
file to save:

```shell
./export_ocsf_findings_security_hub.py [filters] > findings.json
```

## Getting started

You can start using the tools by cloning the repository, creating a virtual environment, then installing the
dependencies.

Clone the repository:

```shell
git clone https://github.com/k9securityio/ocsf-findings-tools.git && cd ocsf-findings-tools
```

Create and activate a virtual environment:

```shell
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```shell
pip3 install -r requirements.txt
```
