---
name: Pull request
about: Update code to fix a bug or add an enhancement/feature
title: ''
labels: ''
assignees: ''

---
## Description

Please include a summary of the change and which issue is fixed, or what the enhancement does.
Please also include relevant motivation and context.
List any dependencies that are required for this change.

## Type of change
Please delete options that are not relevant.
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update
- [ ] This requires a third party update (such as Impacket, Dploot, lsassy, etc)

## How Has This Been Tested?
Please describe the tests that you ran to verify your changes (e2e, single commands, etc)
Please also list any relevant details for your test configuration, such as your locally running machine Python version & OS, as well as the target(s) you tested against, including software versions

If you are using poetry, you can easily run tests via:
`poetry run python tests/e2e_tests.py -t $TARGET -u $USER -p $PASSWORD`
There are additional options like `--errors` to display ALL errors (some may not be failures), `--poetry` (output will include the poetry run prepended), `--line-num $START-$END $SINGLE` for only running a subset

## Screenshots (if appropriate):
Screenshots are always nice to have and can give a visual representation of the change.
If appropriate include before and after screenshot(s) to show which results are to be expected.

## Checklist:

- [ ] I have ran Ruff against my changes (via poetry: `poetry run python -m ruff check . --preview`, use `--fix` to automatically fix what it can)
- [ ] I have added or updated the tests/e2e_commands.txt file if necessary
- [ ] New and existing e2e tests pass locally with my changes
- [ ] My code follows the style guidelines of this project (should be covered by Ruff above)
- [ ] If reliant on third party dependencies, such as Impacket, dploot, lsassy, etc, I have linked the relevant PRs in those projects
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation (PR here: https://github.com/Pennyw0rth/NetExec-Wiki)
