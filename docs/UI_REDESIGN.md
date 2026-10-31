# SOC workspace refresh

The main workspace follows the supplied dark dashboard reference: restrained orange actions, purple secondary accents, compact cards, a map-led overview, and dense investigation priorities. Existing incident, simulation, alert, report, and authentication routes are retained.

## Behavior

- Five existing backend metrics are displayed without generating invented threat statistics.
- Priorities show up to five unresolved incidents ranked by recorded risk from the latest 100 records. Links open the existing investigation workspace. This is a sample, not a global highest-risk query.
- The provenance ring uses incident metrics, not security-event import verification.
- The overview map is a static geographic backdrop. The separate simulation map retains its existing behavior.
- A four-step navigation guide explains the simulation-to-report workflow.
- The shared theme covers the existing workspace; specialized simulation styling may retain its own presentation.

## Verification boundaries

JavaScript syntax and repository whitespace checks were run. The overview layout was inspected in Chromium at desktop width and in a 390px iframe (375px content area after scrollbar), without page-level horizontal overflow. The browser preview infrastructure cannot run this Python virtual environment, so browser inspection used the actual HTML/CSS with scripts disabled and the overview visible. The screenshot is an empty-state layout preview, not proof of authenticated workflows. The existing backend suite was run independently; see the delivery report for its result. The existing Chromium end-to-end script was not rerun.

## Repository metadata still requiring GitHub settings access

Suggested About description:

> Local-first SOC training platform with attack simulation, log ingestion, threat detection, investigation workflows, and evidence-linked reports.

Suggested topics:

`cybersecurity`, `soc`, `incident-response`, `python`, `flask`, `security-monitoring`, `blue-team`, `security-training`

No demo URL is advertised because no public application deployment was verified. Existing tags are preserved. A release publication must describe its actual tagged source, not imply that these interface changes exist in an older tag.
