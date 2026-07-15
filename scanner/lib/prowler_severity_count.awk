# ClaudeSec — count Prowler OCSF FAIL findings by severity.
#
# Reads one prowler-*.ocsf.json file and prints four space-separated counts:
#   "<critical> <high> <medium> <low>"
# for records whose status_code is FAIL, bucketed by the preceding severity.
#
# Extracted verbatim from output_prowler.sh::_prowler_dashboard_summary so the
# awk program body is no longer counted by kcov as uncoverable bash lines (a
# kcov-v42 limitation for multi-line interpreter strings inside $() ). Invoked
# as: awk -f prowler_severity_count.awk <file>. Behaviour is identical to the
# former inline single-quoted program. Covered behaviourally by
# scanner/tests/test_output_prowler_severity.sh.
BEGIN { c=0; h=0; m=0; l=0 }
/"severity":/ { gsub(/.*"severity": *"/,""); gsub(/".*/, ""); sev=$0 }
/"status_code": *"FAIL"/ {
  if (sev=="Critical") c++; else if (sev=="High") h++; else if (sev=="Medium") m++; else if (sev=="Low") l++
}
END { print c+0, h+0, m+0, l+0 }
