# Local IAM policy fixtures

These two JSON files are preserved verbatim from production commit
`9eb759778e14b7c3e33aa1ebf73c85e0d4f20705`. Production no longer installs or ships
them. The emulator and offline IAM checks render their placeholders and combine
them with the testing-only signer role and manual rollout changes in
`policy_fixtures.py`. They demonstrate the tested authorization assumptions;
they are not an account-wide permissions boundary or deployment framework.
