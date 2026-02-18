## Description

Please include a summary of the change and which issue is fixed, or what the enhancement does.
List any dependencies that are required for this change.

## Type of change
Insert an "x" inside the brackets for relevant items (do not delete options)

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Deprecation of feature or functionality
- [ ] This change requires a documentation update
- [ ] This requires a third party update (such as Impacket, Dploot, lsassy, etc)
- [ ] This PR was created with the assistance of AI (list what type of assistance, tool(s)/model(s) in the description)

## Setup guide for the review
Please provide guidance on what setup is needed to test the introduced changes, such as your locally running machine Python version & OS, as well as the target(s) you tested against, including software versions.
In particular:
- Bug Fix: Please provide a short description on how to trigger the bug, to make the bug reproducable for the reviewer.
- Added Feature/Enhancement: Please specify what setup is needed in order to test the changes, such as:
  - Is additional software needed?
  - GPO changes required?
  - Specific registry settings that need to be changed?

## Screenshots (if appropriate):
Screenshots are always nice to have and can give a visual representation of the change.
If appropriate, include before and after screenshot(s) to show which results are to be expected.

## Checklist:
Insert an "x" inside the brackets for completed and relevant items (do not delete options)

- [ ] I have ran Ruff against my changes (poetry: `poetry run ruff check .`, use `--fix` to automatically fix what it can)
- [ ] I have added or updated the `tests/e2e_commands.txt` file if necessary (new modules or features are _required_ to be added to the e2e tests)
- [ ] If reliant on changes of third party dependencies, such as Impacket, dploot, lsassy, etc, I have linked the relevant PRs in those projects
- [ ] I have linked relevant sources that describes the added technique (blog posts, documentation, etc)
- [ ] I have performed a self-review of my own code (_not_ an AI review)
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation (PR here: https://github.com/Pennyw0rth/NetExec-Wiki)
