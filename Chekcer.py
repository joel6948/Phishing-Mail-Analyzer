import sys

SUSPICIOUS_KEYWORDS = [
   "urgent", "verify", "click here",
   "suspended", "confirm", "act now",
   "limited time", "winner", "prize"
]

def analysze_header(headers):
    findings =[]

    for keywords in SUSPICIOUS_KEYWORDS:
        if keywords.lower() in headers.lower():
            findings.append(f"Suspicious keyword found {keywords}")

    from_line = ""
    replyto_line = ""

    for line in headers.split("\n"):
        if line.startswith("From:"):
            from_line = line
        if line.startswith("Reply-To:"):
            replyto_line = line

    if replyto_line and from_line != replyto_line:
        findings.append(f"Mismatch detected !")
        findings.append(f"{from_line}")
        findings.append(f"{replyto_line}")
    
    return findings


def main():
    filename = sys.argv[1]
    with open(filename, "r") as f:
        headers = f.read()

    print(f"\n Analysing {filename} for phisihing indicator")
    findings = analysze_header(headers)

    if findings:
        print(f"{len(findings)} indicators found: \n")
        for findings in findings:
            print(f" {findings}")

    else:
        print("No Phising Indicator Found")


if __name__ == "__main__":
    main()


