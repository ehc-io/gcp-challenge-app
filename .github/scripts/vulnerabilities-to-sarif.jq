# Converts `gcloud artifacts docker images list-vulnerabilities --format=json` output to SARIF 2.1.0
# for GitHub code scanning. Inputs: $vulns (--slurpfile), $gomod and $dockerfile (--rawfile).
# Go module findings point at the module's line in go.mod; other packages point at the last FROM
# line of the Dockerfile (the runtime base image). Severity scores follow Trivy's SARIF mapping.

def score: {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0"}[.] // "0.0";
def level: {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}[.] // "note";

# 1-based numbers of the lines that satisfy f
def lines_where(text; f): [text | split("\n") | to_entries[] | select(.value | f) | .key + 1];

(lines_where($dockerfile; test("^\\s*FROM\\s"; "i")) | last // 1) as $from_line
| ($vulns[0] // []) as $occurrences
| [$occurrences[].vulnerability | . as $v | .packageIssue[] | {
    id: $v.shortDescription,
    severity: $v.effectiveSeverity,
    url: ($v.relatedUrls[0].url // null),
    package: .affectedPackage,
    version: .affectedVersion.name,
    fix: (if .fixAvailable then "fixed in \(.fixedVersion.name)" else "no fix available" end),
    location: (
      if .packageType == "GO" then
        (.affectedPackage) as $p
        | {uri: "app/go.mod",
           line: (lines_where($gomod; sub("^\\s*(require\\s+)?"; "") | startswith($p + " ")) | first // 1)}
      else
        {uri: "app/Dockerfile", line: $from_line}
      end)
  }] as $issues
| {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {driver: {
        name: "Artifact Analysis",
        informationUri: "https://cloud.google.com/artifact-analysis/docs/container-scanning-overview",
        rules: [$issues | group_by(.id)[] | .[0] | {
          id,
          name: .id,
          shortDescription: {text: "\(.id) (\(.severity))"},
          fullDescription: {text: "\(.id): \(.severity) severity vulnerability reported by Artifact Analysis"},
          help: {text: (.url // .id)},
          properties: {"security-severity": (.severity | score), tags: ["security", "vulnerability"]}
        } + (if .url then {helpUri: .url} else {} end)]
      }},
      results: [$issues[] | {
        ruleId: .id,
        level: (.severity | level),
        message: {text: "\(.package) \(.version) is affected by \(.id) (\(.severity)); \(.fix)"},
        locations: [{physicalLocation: {
          artifactLocation: {uri: .location.uri},
          region: {startLine: .location.line}
        }}]
      }]
    }]
  }
