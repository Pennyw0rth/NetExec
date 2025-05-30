## Description

Please include a summary of the change and which issue is fixed, or what the enhancement does.
List any dependencies that are required for this change.

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update
- [ ] This requires a third party update (such as Impacket, Dploot, lsassy, etc)

## Setup guide for the review
Please provide guidance on what setup is needed to test the introduced changes, such as your locally running machine Python version & OS, as well as the target(s) you tested against, including software versions.
In particular:
- Bug Fix: Please provide a short description on how to trigger the bug, to make the bug reproducable for the reviewer.
- Added Feature/Enhancement: Please specify what setup is needed in order to test the changes. E.g. is additional software needed? GPO changes required? Specific registry settings that need to be changed?

## Screenshots (if appropriate):
Screenshots are always nice to have and can give a visual representation of the change.
If appropriate include before and after screenshot(s) to show which results are to be expected.

## Checklist:

- [ ] I have ran Ruff against my changes (via poetry: `poetry run python -m ruff check . --preview`, use `--fix` to automatically fix what it can)
- [ ] I have added or updated the tests/e2e_commands.txt file if necessary
- [ ] New and existing e2e tests pass locally with my changes
- [ ] If reliant on changes of third party dependencies, such as Impacket, dploot, lsassy, etc, I have linked the relevant PRs in those projects
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation (PR here: https://github.com/Pennyw0rth/NetExec-Wiki)
