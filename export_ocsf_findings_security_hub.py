#!/usr/bin/env python3
"""
Get findings from AWS Security Hub in OCSF format.

Example usage:
    python3 export_ocsf_findings_security_hub.py --account 123456789012 --status New --severity Fatal --severity Critical --severity High
    python3 export_ocsf_findings_security_hub.py --created-days-ago 30 --severity Critical
    python3 export_ocsf_findings_security_hub.py --status New --status "In Progress" --activity-name-not Close
    python3 export_ocsf_findings_security_hub.py --activity-name Create --activity-name Update
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError, BotoCoreError


def _append_string_filters(composite_filters: list[dict], string_filter_items: list, operator="OR"):
    """Helper to add string filters to composite_filters with proper operator logic.

    Args:
        composite_filters: List of StringFilter and DateFilter objects
        string_filter_items: List of string filter query specs to add to a StringFilter
        operator: "OR" for OR logic between filters, "AND" for AND logic (each filter separate)
    """
    if not string_filter_items:
        return

    if operator == "AND":
        # For AND operations (like NOT filters), add each separately
        # so they are AND'ed together at the top level
        for filter_item in string_filter_items:
            composite_filters.append({
                "StringFilters": [filter_item]
            })
    elif len(string_filter_items) > 1 and operator == "OR":
        composite_filters.append({
            "Operator": "OR",
            "StringFilters": string_filter_items
        })
    else:
        composite_filters.append({
            "StringFilters": string_filter_items
        })


def build_filters(args) -> dict:
    """Build the filters dict for the get_findings_v2 API based on command line arguments."""
    filters = {}
    composite_filters = []

    # Account filter
    if args.account:
        account_filters = [
            {
                "FieldName": "cloud.account.uid",
                "Filter": {
                    "Value": args.account,
                    "Comparison": "EQUALS"
                }
            }
        ]
        _append_string_filters(composite_filters, account_filters)

    # Status filter (multiple values with OR)
    if args.status:
        status_filters = [
            {
                "FieldName": "status",
                "Filter": {
                    "Value": status,
                    "Comparison": "EQUALS"
                }
            }
            for status in args.status
        ]
        _append_string_filters(composite_filters, status_filters, "OR")

    # Severity filter (multiple values with OR)
    if args.severity:
        severity_filters = [
            {
                "FieldName": "severity",
                "Filter": {
                    "Value": severity,
                    "Comparison": "EQUALS"
                }
            }
            for severity in args.severity
        ]
        _append_string_filters(composite_filters, severity_filters, "OR")

    # Activity name filter (multiple values with OR)
    if args.activity_name:
        activity_filters = [
            {
                "FieldName": "activity_name",
                "Filter": {
                    "Value": activity_name,
                    "Comparison": "EQUALS"
                }
            }
            for activity_name in args.activity_name
        ]
        _append_string_filters(composite_filters, activity_filters, "OR")

    # Activity name NOT filter (exclude certain activity names)
    if args.activity_name_not:
        activity_not_filters = [
            {
                "FieldName": "activity_name",
                "Filter": {
                    "Value": activity_name,
                    "Comparison": "NOT_EQUALS"
                }
            }
            for activity_name in args.activity_name_not
        ]
        # Multiple NOT_EQUALS need to be AND'ed together
        # (i.e., not Close AND not Archive)
        _append_string_filters(composite_filters, activity_not_filters, "AND")

    # Date filter (created days ago)
    if args.created_days_ago:
        composite_filters.append({
            "DateFilters": [
                {
                    "FieldName": "finding_info.created_time_dt",
                    "Filter": {
                        "DateRange": {
                            "Unit": "DAYS",
                            "Value": args.created_days_ago
                        }
                    }
                }
            ]
        })

    # Build final filters structure
    if composite_filters:
        if len(composite_filters) == 1:
            filters["CompositeFilters"] = composite_filters
        else:
            # Multiple filters need AND operator
            filters["CompositeOperator"] = "AND"
            filters["CompositeFilters"] = composite_filters

    return filters


def get_ocsf_findings(filters: dict, verbose: bool = False) -> list[dict]:
    """Retrieve all findings from Security Hub using pagination.

    :returns a list of OCSF finding object dictionaries
    """
    try:
        client = boto3.client('securityhub')

        paginator = client.get_paginator('get_findings_v2')

        pagination_kwargs = {
            'PaginationConfig': {
                'MaxItems': 10000,  # Maximum findings to return in total
                'PageSize': 100,  # Items (findings) per page
            }
        }
        if filters:
            pagination_kwargs['Filters'] = filters

        page_iterator = paginator.paginate(**pagination_kwargs)

        # Collect all findings
        all_findings = []
        page_count = 0
        for page in page_iterator:
            if 'Findings' in page:
                page_count += 1
                findings_in_page = len(page['Findings'])
                all_findings.extend(page['Findings'])
                if verbose:
                    print(f"Retrieved page {page_count}: {findings_in_page} findings (total: {len(all_findings)})", file=sys.stderr)

        if verbose:
            print(f"Total findings retrieved: {len(all_findings)}", file=sys.stderr)

        return all_findings

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"Error: AWS API error - {error_code}: {error_message}", file=sys.stderr)
        sys.exit(-1)
    except BotoCoreError as e:
        print(f"Error: AWS SDK error - {str(e)}", file=sys.stderr)
        sys.exit(-1)
    except Exception as e:
        print(f"Error: Unexpected error - {str(e)}", file=sys.stderr)
        sys.exit(-1)


def main():
    """Main entry point for the script."""
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Exports findings from Security Hub in OCSF format. Exports all findings by default.'
                    ' Filter findings with the program options.'
    )

    parser.add_argument(
        '--account',
        type=str,
        help='Filter by AWS account ID'
    )

    parser.add_argument(
        '--status',
        type=str,
        action='append',
        choices=['New', 'In Progress', 'On Hold', 'Suppressed', 'Resolved', 'Archived', 'Deleted', 'Unknown', 'Other'],
        help='Filter by finding status, e.g., New, \'In Progress\', Suppressed, Resolved; can specify multiple times for OR logic'
    )

    parser.add_argument(
        '--severity',
        type=str,
        action='append',
        choices=['Fatal', 'Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown', 'Other'],
        help='Filter by severity (can specify multiple times for OR logic)'
    )

    parser.add_argument(
        '--created-days-ago',
        type=int,
        help='Filter findings created within the last N days, e.g. 30'
    )

    parser.add_argument(
        '--activity-name',
        type=str,
        action='append',
        choices=['Create', 'Update', 'Close', 'Unknown', 'Other'],
        help='Filter by activity name, e.g., Create, Update; can specify multiple times for OR logic'
    )

    parser.add_argument(
        '--activity-name-not',
        type=str,
        action='append',
        choices=['Create', 'Update', 'Close', 'Unknown', 'Other'],
        help='Exclude findings with this activity name, e.g., Close; can specify multiple times for NOR logic'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (show filters and progress information)'
    )

    # Parse arguments
    args = parser.parse_args()

    # Build filters
    filters = build_filters(args)

    # Print filters as JSON to stderr if verbose
    if args.verbose:
        print(f"Filters: {json.dumps(filters, indent=2)}", file=sys.stderr)

    # Get findings
    findings = get_ocsf_findings(filters, args.verbose)

    # Output findings as JSON
    print(json.dumps(findings, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
