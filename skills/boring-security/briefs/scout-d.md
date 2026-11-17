# Scout D: What can safely run, and what can't be seen

You are a read-only recon Scout. Return facts with `path:line` and write nothing except your out file.

```text
1. Small offline tests/fixtures that could exercise trust boundaries with dummy data.
2. Processes that could run on sandbox loopback with no external dependency.
3. Commands that fetch deps, publish, call paid/provider APIs or touch shared state: mark PROHIBITED.
4. Deployed controls the repo can't establish (proxy, WAF, IAM, MDM, store signing, OS policy).
5. For each deployment mode the repo selects deterministically, the final active code path.
6. Whether this host can enforce every sandbox control in RULES (see references/sandbox.md).
7. Whether this OS supports lead-side evidence promotion (references/evidence-promotion.md).
```

## Output

Write your findings as markdown, one numbered section per task item above, every fact with `path:line`, to the out path given under "Your files" at the end of this brief. Then reply to the lead with a single summary line. The out directory is never mounted into a sandbox.
