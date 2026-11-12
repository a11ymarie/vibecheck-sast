"""Plain-language guidance for Semgrep community-rule hits, by vulnerability class.

Community rules come with a one-line message written for security engineers. To make their hits
actionable for anyone, each is mapped (via its CWE) to a class of problem with steps to confirm
it, when it matters, and how it's usually fixed.
"""
import re

CLASSES = {
    "injection": dict(
        cwes={77, 78, 88, 89, 90, 94, 95, 643, 917, 943, 1336},
        name="Injection",
        confirm="Trace the value that reaches the flagged call back to where it enters the app. "
                "If a user can influence it (URL, form, body, headers, uploaded file), try a value "
                "with quotes or shell/query syntax against a local copy.",
        impact="High if user-controlled input reaches it. Low or a false positive if the value is a "
               "constant or comes only from your own trusted configuration.",
        fix="Pass user values as parameters (query placeholders, argument arrays) instead of "
            "building strings, or validate them against a strict allow-list."),
    "xss": dict(
        cwes={79, 80, 83, 87},
        name="Cross-site scripting (XSS)",
        confirm="Find where the rendered value comes from. If a user can save or send it (profile "
                "text, comments, URL parameters), put <img src=x onerror=alert(1)> in it locally "
                "and see whether it runs.",
        impact="High if other users see the content; medium if only the author sees it; false "
               "positive if the value is fixed or already sanitized.",
        fix="Render it as text (let React escape it), or sanitize it with a library such as "
            "DOMPurify before inserting HTML."),
    "path": dict(
        cwes={22, 23, 35, 73},
        name="Path traversal",
        confirm="Check whether a request value becomes part of a file path. Locally, try ../ "
                "sequences and see whether a file outside the intended folder can be read.",
        impact="High if it reads or writes files with user input; false positive if the name comes "
               "from your own code.",
        fix="Use only a basename or an id you map to a file yourself, and check the resolved path "
            "stays inside the intended folder."),
    "ssrf": dict(
        cwes={918},
        name="Server-side request forgery (SSRF)",
        confirm="Check whether a user can choose the URL your server fetches. Locally, try "
                "http://127.0.0.1 or a cloud metadata address and see whether the server requests it.",
        impact="High on servers that can reach internal services or cloud metadata; lower for "
               "fully isolated serverless functions.",
        fix="Allow only specific hosts, and block private and link-local addresses after DNS "
            "resolution."),
    "redirect": dict(
        cwes={601},
        name="Open redirect",
        confirm="See whether a URL parameter decides where the user is sent. Try a full outside "
                "URL as its value.",
        impact="Medium: it makes phishing links look like they belong to your site; high if it's "
               "part of a login flow that passes tokens along.",
        fix="Only redirect to relative paths you recognize, or to a fixed list of destinations."),
    "crypto": dict(
        cwes={326, 327, 328, 330, 338, 759, 760, 916},
        name="Weak cryptography or randomness",
        confirm="Check what the flagged algorithm or random value is used for: passwords, tokens "
                "and signatures matter; checksums and cache keys usually don't.",
        impact="High for passwords, session or reset tokens; false positive for non-security uses.",
        fix="Use bcrypt/argon2 for passwords, crypto.randomUUID() or crypto.randomBytes() for "
            "tokens, and SHA-256 or better elsewhere."),
    "secrets": dict(
        cwes={259, 321, 522, 798},
        name="Hard-coded credential",
        confirm="Check whether the value is a real, active credential rather than a placeholder.",
        impact="High if it's real, especially if the repo was ever shared or public.",
        fix="Rotate it in the provider's dashboard, then load it from a server-side environment "
            "variable."),
    "auth": dict(
        cwes={287, 345, 347, 352, 384, 613, 639, 862, 863},
        name="Authentication or authorization weakness",
        confirm="Check which route or action this protects, and try it while logged out or as a "
                "different user.",
        impact="High if it lets someone act as another user or skip login; medium otherwise.",
        fix="Verify tokens with a pinned algorithm, check the current user's permission on every "
            "request, and use your framework's CSRF protection for cookie sessions."),
    "unsafe-data": dict(
        cwes={502, 915, 1321},
        name="Unsafe handling of untrusted data",
        confirm="Check whether user-supplied JSON or objects reach the flagged merge, assignment or "
                "deserialization.",
        impact="High if attacker-controlled keys like __proto__ or role can change behavior; low "
               "if the data is trusted.",
        fix="Copy only the fields you expect, and use plain parsing (JSON.parse) instead of object "
            "merging or deserializers on untrusted input."),
    "config": dict(
        cwes={16, 614, 693, 942, 1004, 1021, 1275},
        name="Security misconfiguration",
        confirm="Check whether the flagged setting applies in production, not just in local "
                "development.",
        impact="Usually medium; high when it weakens login cookies or lets other sites read your "
               "API responses.",
        fix="Use the secure setting (Secure/HttpOnly/SameSite cookies, explicit CORS origins, "
            "security headers) in production."),
    "dos": dict(
        cwes={400, 770, 1333},
        name="Denial of service",
        confirm="Check whether user input reaches the flagged regex or resource-heavy call, and "
                "whether there's a size limit.",
        impact="Medium for public endpoints; low for internal tools.",
        fix="Limit input size, avoid nested quantifiers in regexes, and add rate limits."),
}

DEFAULT = dict(
    name="Security pattern",
    confirm="Read the flagged code and the rule's message, and check whether untrusted input or "
            "production settings are involved.",
    impact="Depends on whether untrusted input reaches it; treat as a lead to review.",
    fix="Follow the rule's message and the linked reference.")


def cwe_numbers(cwe_field) -> set:
    text = " ".join(cwe_field) if isinstance(cwe_field, list) else str(cwe_field or "")
    return {int(n) for n in re.findall(r"CWE-(\d+)", text)}


def for_cwe(cwe_field) -> dict:
    nums = cwe_numbers(cwe_field)
    for cls in CLASSES.values():
        if nums & cls["cwes"]:
            return cls
    return DEFAULT
