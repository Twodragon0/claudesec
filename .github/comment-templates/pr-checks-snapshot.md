GitHub Checks snapshot before merge (`gh pr checks <PR_NUMBER>`):

```text
shell-lint                  <pass|fail>   <duration>
scanner-unit-tests          <pass|fail>   <duration>
dashboard-regression-check  <pass|fail>   <duration>
markdown-lint               <pass|fail>   <duration>
link-check                  <pass|fail>   <duration>
Analyze (actions)           <pass|fail>   <duration>
Analyze (python)            <pass|fail>   <duration>
CodeQL                      <pass|fail>   <duration>
GitGuardian Security Checks <pass|fail>   <duration>
```

Use this template when adding a PR checks comment so reviewers always see the same format.
