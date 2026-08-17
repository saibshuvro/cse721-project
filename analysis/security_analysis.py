"""Structured security comparison for the CLI and final Markdown report."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from textwrap import fill


DEFAULT_SECURITY_REPORT_PATH = Path("results/security_analysis.md")


@dataclass(frozen=True)
class SecurityReference:
    """One authoritative or project-local source used by an assessment."""

    identifier: str
    title: str
    url: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.identifier, "Reference identifier"),
            (self.title, "Reference title"),
            (self.url, "Reference URL"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value.strip():
                raise ValueError(f"{name} must not be empty")


@dataclass(frozen=True)
class SecurityAssessment:
    """Consistent design and implementation analysis for one component."""

    identifier: str
    algorithm: str
    category: str
    project_parameters: str
    security_basis: str
    effective_strength: str
    demonstrated_analysis: str
    primary_weakness: str
    implementation_limitations: str
    conclusion: str
    reference_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.identifier, "Assessment identifier"),
            (self.algorithm, "Algorithm name"),
            (self.category, "Category"),
            (self.project_parameters, "Project parameters"),
            (self.security_basis, "Security basis"),
            (self.effective_strength, "Effective strength"),
            (self.demonstrated_analysis, "Demonstrated analysis"),
            (self.primary_weakness, "Primary weakness"),
            (self.implementation_limitations, "Implementation limitations"),
            (self.conclusion, "Conclusion"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value.strip():
                raise ValueError(f"{name} must not be empty")

        if type(self.reference_ids) is not tuple:
            raise TypeError("Reference identifiers must be a tuple")
        if not self.reference_ids:
            raise ValueError("Every assessment must cite at least one reference")
        for index, reference_id in enumerate(self.reference_ids):
            if not isinstance(reference_id, str):
                raise TypeError(f"Reference identifier {index} must be a string")
            if not reference_id.strip():
                raise ValueError(f"Reference identifier {index} must not be empty")
        if len(set(self.reference_ids)) != len(self.reference_ids):
            raise ValueError("Assessment reference identifiers must be unique")


SECURITY_REFERENCES = (
    SecurityReference(
        identifier="project-scope",
        title="Project requirements analysis and security boundary",
        url="../docs/requirements-analysis.md",
    ),
    SecurityReference(
        identifier="nist-des",
        title="NIST FIPS 46-3: Data Encryption Standard (withdrawn)",
        url="https://csrc.nist.gov/pubs/fips/46-3/final",
    ),
    SecurityReference(
        identifier="nist-aes",
        title="NIST FIPS 197: Advanced Encryption Standard",
        url="https://csrc.nist.gov/pubs/fips/197/final",
    ),
    SecurityReference(
        identifier="nist-ecb",
        title="NIST explanation of ECB repeated-block leakage",
        url="https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a",
    ),
    SecurityReference(
        identifier="rfc8017",
        title="RFC 8017 Section 7: RSA encryption schemes",
        url="https://www.rfc-editor.org/rfc/rfc8017#section-7",
    ),
    SecurityReference(
        identifier="nist-rsa",
        title="NIST SP 800-56B Rev. 2: Integer-factorization key establishment",
        url="https://csrc.nist.gov/pubs/sp/800/56/b/r2/final",
    ),
    SecurityReference(
        identifier="nist-ecc",
        title="NIST SP 800-56A Rev. 3: Discrete-logarithm key establishment",
        url="https://csrc.nist.gov/pubs/sp/800/56/a/r3/final",
    ),
)


SECURITY_ASSESSMENTS = (
    SecurityAssessment(
        identifier="substitution",
        algorithm="Substitution Cipher",
        category="Classical symmetric cipher",
        project_parameters="General monoalphabetic permutation of ASCII A-Z.",
        security_basis=(
            "Secrecy of the letter permutation, with a theoretical 26! key space."
        ),
        effective_strength=(
            "Far below what the 26! count suggests because natural-language "
            "redundancy survives substitution."
        ),
        demonstrated_analysis=(
            "Exhaustive search over reduced alphabets and an English frequency-rank "
            "mapping with a plaintext preview."
        ),
        primary_weakness=(
            "Single-letter frequencies, repeated-letter patterns, word shapes, and "
            "known plaintext reveal information about the permutation."
        ),
        implementation_limitations=(
            "The frequency mapping is only a heuristic; the application deliberately "
            "does not claim to enumerate all 26! keys."
        ),
        conclusion="Educational only; unsuitable for protecting confidential data.",
        reference_ids=("project-scope",),
    ),
    SecurityAssessment(
        identifier="double-transposition",
        algorithm="Double Transposition Cipher",
        category="Classical symmetric cipher",
        project_parameters=(
            "Row permutation followed by column permutation on a padded text grid."
        ),
        security_basis=(
            "Secrecy of the row and column permutations; an r-by-c grid has at most "
            "r! × c! key combinations in this model."
        ),
        effective_strength=(
            "Small grids have small factorial key spaces, while larger grids still "
            "leak the unchanged symbol distribution and message structure."
        ),
        demonstrated_analysis=(
            "A plaintext/ciphertext frequency comparison confirms that every ASCII "
            "letter count is preserved."
        ),
        primary_weakness=(
            "It changes positions rather than symbols, preserving character "
            "frequencies and leaking length and structural patterns."
        ),
        implementation_limitations=(
            "The visible grid dimensions and deterministic padding provide additional "
            "structural information to an observer."
        ),
        conclusion="Educational only; vulnerable to structural and known-plaintext analysis.",
        reference_ids=("project-scope",),
    ),
    SecurityAssessment(
        identifier="des",
        algorithm="DES",
        category="Symmetric-key block cipher",
        project_parameters=(
            "64-bit blocks, 64 supplied key bits with 56 effective bits, 16 rounds, "
            "PKCS#7 padding, and an ECB demonstration wrapper."
        ),
        security_basis="Exhaustive search of the effective 56-bit key space.",
        effective_strength=(
            "At most 56 bits against brute force; NIST withdrew the DES standard in "
            "2005 because it no longer provided adequate security."
        ),
        demonstrated_analysis=(
            "Known-answer tests, all round keys and Feistel stages, and a theoretical "
            "explanation of exhaustive key search."
        ),
        primary_weakness=(
            "The key space is too small, and ECB independently encrypts blocks so "
            "equal plaintext blocks produce equal ciphertext blocks."
        ),
        implementation_limitations=(
            "The wrapper has no authentication, exposes detailed traces for teaching, "
            "and uses variable-time Python rather than hardened cryptographic code."
        ),
        conclusion="Obsolete and insecure for real confidentiality.",
        reference_ids=("nist-des", "nist-ecb", "project-scope"),
    ),
    SecurityAssessment(
        identifier="aes-128",
        algorithm="AES-128",
        category="Symmetric-key block cipher",
        project_parameters=(
            "128-bit blocks, 128-bit key, 10 rounds, PKCS#7 padding, and an ECB "
            "demonstration wrapper."
        ),
        security_basis=(
            "The standardized AES-128 design and its 128-bit key space when used in "
            "an appropriate protocol."
        ),
        effective_strength=(
            "The algorithm targets 128-bit key security, but application security is "
            "reduced by an unsafe mode, missing authentication, or side channels."
        ),
        demonstrated_analysis=(
            "FIPS known-answer tests, complete key expansion, and forward/inverse "
            "round traces; no reduced-round attack is claimed."
        ),
        primary_weakness=(
            "The project wrapper uses deterministic ECB and provides confidentiality "
            "without integrity or authentication."
        ),
        implementation_limitations=(
            "Lookup-table operations and Python control flow are variable-time, while "
            "trace collection exposes internal states for demonstration."
        ),
        conclusion=(
            "AES-128 remains standardized, but this ECB teaching wrapper is not a "
            "secure application-encryption design."
        ),
        reference_ids=("nist-aes", "nist-ecb", "project-scope"),
    ),
    SecurityAssessment(
        identifier="rsa",
        algorithm="RSA",
        category="Public-key encryption",
        project_parameters=(
            "512/1024-bit educational moduli, public exponent 65537, deterministic "
            "marker-prefixed textbook-RSA text blocks, and a separate toy attack."
        ),
        security_basis=(
            "Difficulty of recovering the private key from the public modulus, which "
            "depends on integer factorization."
        ),
        effective_strength=(
            "The assignment's 512- and 1024-bit moduli are below modern deployment "
            "guidance; NIST SP 800-56B begins its listed RSA sizes at 2048 bits."
        ),
        demonstrated_analysis=(
            "Trial division factors a tiny independent modulus and reconstructs the "
            "private exponent; normal coursework keys are never sent to that attack."
        ),
        primary_weakness=(
            "Textbook RSA is deterministic and malleable; small RSA moduli also make "
            "factorization substantially easier."
        ),
        implementation_limitations=(
            "There is no OAEP, hybrid encryption, ciphertext authentication, blinding, "
            "or constant-time implementation."
        ),
        conclusion=(
            "Suitable only for explaining RSA mathematics; real encryption requires "
            "adequate keys and a defined scheme such as RSAES-OAEP."
        ),
        reference_ids=("rfc8017", "nist-rsa", "project-scope"),
    ),
    SecurityAssessment(
        identifier="ecc-ecdh",
        algorithm="ECC / ECDH",
        category="Public-key key agreement",
        project_parameters=(
            "Curve y²=x³+2x+2 over F17, generator G=(5,1), prime subgroup order "
            "n=19, and private scalars 1 through 18."
        ),
        security_basis=(
            "Difficulty of the elliptic-curve discrete logarithm problem in the "
            "selected generator subgroup."
        ),
        effective_strength=(
            "Only 18 private scalars exist on the demonstration curve, so exhaustive "
            "key recovery is trivial and provides no real security."
        ),
        demonstrated_analysis=(
            "Enumeration of every curve point and generator multiple, point-order "
            "inspection, public-key validation, and matching Alice/Bob shared points."
        ),
        primary_weakness=(
            "The tiny subgroup is exhaustible, while unauthenticated ECDH alone does "
            "not prevent a man-in-the-middle attack."
        ),
        implementation_limitations=(
            "The application returns a raw shared x-coordinate without a KDF or peer "
            "authentication and uses variable-time affine arithmetic."
        ),
        conclusion=(
            "A mathematics demonstration only; production ECDH needs approved domain "
            "parameters, validation, key derivation, and authentication."
        ),
        reference_ids=("nist-ecc", "project-scope"),
    ),
)


def validate_security_comparison(
    assessments: tuple[SecurityAssessment, ...] = SECURITY_ASSESSMENTS,
    references: tuple[SecurityReference, ...] = SECURITY_REFERENCES,
) -> tuple[SecurityAssessment, ...]:
    """Validate record types, uniqueness, and all reference relationships."""

    if type(assessments) is not tuple:
        raise TypeError("Security assessments must be a tuple")
    if not assessments:
        raise ValueError("At least one security assessment is required")
    if type(references) is not tuple:
        raise TypeError("Security references must be a tuple")
    if not references:
        raise ValueError("At least one security reference is required")

    for index, assessment in enumerate(assessments):
        if not isinstance(assessment, SecurityAssessment):
            raise TypeError(f"Security assessment {index} has an invalid type")
    for index, reference in enumerate(references):
        if not isinstance(reference, SecurityReference):
            raise TypeError(f"Security reference {index} has an invalid type")

    assessment_ids = tuple(assessment.identifier for assessment in assessments)
    algorithm_names = tuple(assessment.algorithm for assessment in assessments)
    reference_ids = tuple(reference.identifier for reference in references)
    if len(set(assessment_ids)) != len(assessment_ids):
        raise ValueError("Security assessment identifiers must be unique")
    if len(set(algorithm_names)) != len(algorithm_names):
        raise ValueError("Security assessment algorithm names must be unique")
    if len(set(reference_ids)) != len(reference_ids):
        raise ValueError("Security reference identifiers must be unique")

    available_reference_ids = set(reference_ids)
    for assessment in assessments:
        missing_ids = set(assessment.reference_ids) - available_reference_ids
        if missing_ids:
            missing = ", ".join(sorted(missing_ids))
            raise ValueError(
                f"Assessment {assessment.identifier!r} cites unknown references: {missing}"
            )

    return assessments


def _terminal_field(label: str, value: str, width: int) -> str:
    prefix = f"  {label}: "
    return fill(
        value,
        width=width,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
    )


def render_terminal_security_comparison(
    assessments: tuple[SecurityAssessment, ...] = SECURITY_ASSESSMENTS,
    references: tuple[SecurityReference, ...] = SECURITY_REFERENCES,
    width: int = 100,
) -> str:
    """Return a wrapped plain-text comparison suitable for the CLI."""

    assessments = validate_security_comparison(assessments, references)
    if isinstance(width, bool) or not isinstance(width, int):
        raise TypeError("Terminal width must be an integer")
    if width < 60:
        raise ValueError("Terminal width must be at least 60 characters")

    reference_lookup = {reference.identifier: reference for reference in references}
    lines = [
        "Comparative Security Analysis",
        "Educational implementations — not production cryptography",
    ]

    for index, assessment in enumerate(assessments, start=1):
        reference_titles = "; ".join(
            reference_lookup[reference_id].title
            for reference_id in assessment.reference_ids
        )
        lines.extend(
            (
                "",
                f"{index}. {assessment.algorithm}",
                _terminal_field("Category", assessment.category, width),
                _terminal_field("Project parameters", assessment.project_parameters, width),
                _terminal_field("Security basis", assessment.security_basis, width),
                _terminal_field("Effective strength", assessment.effective_strength, width),
                _terminal_field("Demonstrated", assessment.demonstrated_analysis, width),
                _terminal_field("Main weakness", assessment.primary_weakness, width),
                _terminal_field(
                    "Implementation limits",
                    assessment.implementation_limitations,
                    width,
                ),
                _terminal_field("Conclusion", assessment.conclusion, width),
                _terminal_field("References", reference_titles, width),
            )
        )

    return "\n".join(lines)


def _markdown_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def render_security_markdown(
    assessments: tuple[SecurityAssessment, ...] = SECURITY_ASSESSMENTS,
    references: tuple[SecurityReference, ...] = SECURITY_REFERENCES,
) -> str:
    """Return a portable Markdown security comparison with references."""

    assessments = validate_security_comparison(assessments, references)
    reference_lookup = {reference.identifier: reference for reference in references}
    lines = [
        "# Comparative Cryptographic Security Analysis",
        "",
        (
            "This report separates each algorithm's security basis from limitations "
            "introduced by the project's deliberately educational parameters and interfaces."
        ),
        "",
        "> None of these from-scratch implementations should protect real data.",
        "",
        "## Summary",
        "",
        "| Algorithm | Category | Effective strength | Primary weakness | Conclusion |",
        "|---|---|---|---|---|",
    ]

    for assessment in assessments:
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_cell(assessment.algorithm),
                    _markdown_cell(assessment.category),
                    _markdown_cell(assessment.effective_strength),
                    _markdown_cell(assessment.primary_weakness),
                    _markdown_cell(assessment.conclusion),
                )
            )
            + " |"
        )

    lines.extend(("", "## Detailed assessments"))
    for assessment in assessments:
        reference_links = ", ".join(
            f"[{reference_lookup[reference_id].title}]"
            f"({reference_lookup[reference_id].url})"
            for reference_id in assessment.reference_ids
        )
        lines.extend(
            (
                "",
                f"### {assessment.algorithm}",
                "",
                f"- **Category:** {assessment.category}",
                f"- **Project parameters:** {assessment.project_parameters}",
                f"- **Security basis:** {assessment.security_basis}",
                f"- **Effective strength:** {assessment.effective_strength}",
                f"- **Demonstrated analysis:** {assessment.demonstrated_analysis}",
                f"- **Primary weakness:** {assessment.primary_weakness}",
                (
                    "- **Implementation limitations:** "
                    f"{assessment.implementation_limitations}"
                ),
                f"- **Conclusion:** {assessment.conclusion}",
                f"- **References:** {reference_links}",
            )
        )

    lines.extend(("", "## References", ""))
    for reference in references:
        lines.append(f"- [{reference.title}]({reference.url})")
    lines.append("")
    return "\n".join(lines)


def export_security_markdown(
    output_path: str | Path = DEFAULT_SECURITY_REPORT_PATH,
    assessments: tuple[SecurityAssessment, ...] = SECURITY_ASSESSMENTS,
    references: tuple[SecurityReference, ...] = SECURITY_REFERENCES,
) -> Path:
    """Write the structured comparison to ``security_analysis.md``."""

    if not isinstance(output_path, (str, Path)):
        raise TypeError("Security report path must be a string or Path")
    path = Path(output_path)
    if not path.name:
        raise ValueError("Security report path must identify a file")

    report = render_security_markdown(assessments, references)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return path
