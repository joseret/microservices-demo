echo $1-$2-$3-$4
set -x
mkdir -p compiledjr/$4
cat $1 | yq ".items[] | select(.kind == \"$3\" and .metadata.name ==  \"$2\")" > compiledjr/$4/$2_$3.yaml
# yq '.items[] | select()' < $1