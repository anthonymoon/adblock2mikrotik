import re
from datetime import UTC, datetime

import requests


def fetch_rules(url):
    try:
        response = requests.get(
            url, timeout=(3, 10)
        )  # timeout=(connect_timeout, read_timeout)
        response.raise_for_status()  # Check for HTTP errors
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return []


def convert_rule(rule):
    # Remove comments and whitespace
    rule = re.sub(r"#.*$", "", rule).strip()

    if not rule:
        return None

    # Handle different rule formats
    if rule.startswith("||") and "^" in rule:
        # Extract domain from common ad-blocking rule style (e.g., ||domain^)
        domain = rule[2:].split("^")[0]
        # Remove any additional modifiers after ^
        domain = domain.split("$")[0]
        # Basic domain validation
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
            return f"10.0.0.2 {domain}"
    return None


def main():
    # Whitelist for false positives (legitimate domains incorrectly blocked by upstream lists)
    # Note: All .io domains are automatically whitelisted (see filtering logic below)
    WHITELIST = {
        "import.cdn.thinkific.com",  # Thinkific course platform CDN (false positive in 1Hosts Xtra)
        "email.noreply.thinkific.com",  # Thinkific transactional emails
        "email.notify.thinkific.com",  # Thinkific notification emails
    }

    urls = [
        # Hagezi - Normal (balanced, recommended by community for fewer false positives)
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
        # Hagezi - Threat Intelligence Feeds (security focused)
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
        # 1Hosts - Lite version (balanced, prioritizes smooth UX)
        "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
        # OISD - Basic (fewer false positives than Full)
        "https://small.oisd.nl/",
        # AdGuard DNS Filter (maintained, good balance)
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    ]

    # Use a set to track unique rules
    unique_rules = set()

    # Write header with timestamp
    current_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""# Title: This filter compiled from trusted, verified sources and optimized for compatibility with DNS-level ad blocking by merging and simplifying multiple filters
#
# Homepage: https://github.com/eugenescodes/adblock2mikrotik
# License: https://github.com/eugenescodes/adblock2mikrotik/blob/main/LICENSE
#
# Last modified: {current_time}
#
# Sources (balanced variants to minimize false positives):
#
# - Hagezi DNS blocklists (Multi Normal, TIF)
# - 1Hosts Lite (badmojr)
# - OISD Basic
# - AdGuard DNS Filter
#
# Note: All .io domains are automatically whitelisted
#
# Format: 10.0.0.2 domain.tld
#
"""

    with open("hosts.txt", "w", encoding="utf-8") as f:
        f.write(header)

        for url in urls:
            f.write(f"\n# Source: {url}\n\n")
            rules = fetch_rules(url)
            converted_count = 0

            for rule in rules:
                converted = convert_rule(rule)
                if converted and converted not in unique_rules:
                    # Extract domain from converted rule (format: "10.0.0.2 domain.com")
                    domain = converted.split()[-1]
                    # Skip if domain is in whitelist or is a .io domain
                    if domain not in WHITELIST and not domain.endswith(".io"):
                        unique_rules.add(converted)
                        f.write(converted + "\n")
                        converted_count += 1

            f.write(f"\n# Converted {converted_count} rules from this source\n\n")

        # Write total count at the end
        f.write(f"\n# Total unique domains: {len(unique_rules)}\n")


if __name__ == "__main__":
    main()
