# working

This folder used to extract all previous versions of the cloudfirewall_controller.go so we can extract the default rules
for each commit.

In a shell in the root of the project run:

```bash
FILE=internal/controller/cloudfirewall_controller.go
for commit in $(git log --pretty=format:%H -- $FILE); do
  date=$(git show -s --format=%cd --date=short $commit)
  git show $commit:$FILE > working/cloudfirewall_controller_${date}_${commit}.go
done
```
