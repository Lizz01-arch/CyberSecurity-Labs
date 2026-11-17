import requests
import json


def fetch_threat_intelligence():
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    headers = {
        'X-OTX-API-KEY': 'YOUR_API_KEY_HERE'  # Optional: only needed for live runs
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: Received status code {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def assign_priority(tags):
    lowered = {str(t).lower() for t in tags}
    if lowered & {'ransomware', 'phishing'}:
        return 'HIGH'
    if lowered & {'malware', 'trojan', 'botnet', 'apt', 'backdoor', 'exploit'}:
        return 'MEDIUM'
    return 'LOW'


def parse_threat_intelligence(data):
    """
    TODO:
    - If no usable results are returned (e.g., None or empty results), exit gracefully.
    - For each pulse: extract name, tags, indicators
    - Assign priority: HIGH / MEDIUM / LOW (case-insensitive tag logic)
    - Compute indicator count for each pulse
    - Write a report to 'otx_intelligence_report.txt'
    """
    if not data or not isinstance(data, dict) or not data.get('results'):
        print("No data to parse or invalid response.")
        return

    lines = ["OTX Threat Intelligence Report", "=" * 30, ""]

    for pulse in data['results']:
        name = pulse.get('name') or 'N/A'
        tags = pulse.get('tags') or []
        indicators = pulse.get('indicators') or []
        priority = assign_priority(tags)

        lines.append(f"Pulse: {name}")
        lines.append(f"Priority: {priority}")
        lines.append(f"Tags: {', '.join(tags) if tags else 'None'}")
        lines.append(f"Indicator Count: {len(indicators)}")
        lines.append("Indicators:")
        if indicators:
            for ind in indicators:
                lines.append(f"  - {ind.get('type', 'N/A')}: {ind.get('indicator', 'N/A')}")
        else:
            lines.append("  - None")
        lines.append("")

    report = "\n".join(lines)

    # Show the report on screen
    print(report)

    # Export the report to a file
    with open('otx_intelligence_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    print("Report written to otx_intelligence_report.txt")


if __name__ == '__main__':
    threat_data = fetch_threat_intelligence()
    parse_threat_intelligence(threat_data)
