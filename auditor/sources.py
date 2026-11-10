"""Tags for the articles and standards that back each finding.

Titles and links are in the Sources section of README.md.
"""

from __future__ import annotations

from enum import StrEnum


class Source(StrEnum):
    """A citation tag shown next to a finding in the report."""

    OWASP_CS_1 = "OWASP-CS #1"
    OWASP_CS_2 = "OWASP-CS #2"
    OWASP_CS_3 = "OWASP-CS #3"
    OWASP_CS_4 = "OWASP-CS #4"
    OWASP_CS_8 = "OWASP-CS #8"
    OWASP_DG = "OWASP-DG"
    OWASP_SCP = "OWASP-SCP"
    NETDATA = "Netdata"
    DD_CIS531 = "DD-CIS531"
    DOCK_POST = "DOCK-POST"
    DOCK_USERNS = "DOCK-USERNS"
    K8S_PSS = "K8S-PSS"
    TEN_CIS = "TEN-CIS"
    CWE_636 = "CWE-636"
    NIST_190 = "NIST-190"
    NIST_GLOSS = "NIST-GLOSS"
    VERCEL = "Vercel"
    BLAXEL = "Blaxel"
    K8S_NP = "K8S-NP"
    AWS_EKS_IAM = "AWS-EKS-IAM"
    AWS_IMDS = "AWS-IMDS"
    GCP_MD = "GCP-MD"
    AZ_IMDS = "AZ-IMDS"
    OWASP_SSRF = "OWASP-SSRF"
