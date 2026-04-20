#!/usr/bin/env bash

#  Copyright 2020 The Kubernetes Authors.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

set -o errexit
set -o pipefail

# Turn colors in this script off by setting the NO_COLOR variable in your
# environment to any value:
#
# $ NO_COLOR=1 test.sh
NO_COLOR=${NO_COLOR:-""}
if [ -z "$NO_COLOR" ]; then
  header=$'\e[1;33m'
  reset=$'\e[0m'
else
  header=''
  reset=''
fi

function header_text {
  echo "$header$*$reset"
}

function setup_envtest_env {
  header_text "setting up env vars"
  k8s_version="${ENVTEST_K8S_VERSION:-1.35}"
  echo "GOPATH=$GOPATH"
  echo "Showing contents of GOPATH/bin"
  ls $GOPATH/bin
  eval $GOPATH/bin/setup-envtest use -p env
}

# fetch k8s API gen tools and make it available under envtest_root_dir/bin.
#
# Skip fetching and untaring the tools by setting the SKIP_FETCH_TOOLS variable
# in your environment to any value:
#
# $ SKIP_FETCH_TOOLS=1 ./check-everything.sh
#
# If you skip fetching tools, this script will use the tools already on your
# machine.
function fetch_envtest_tools {
  SKIP_FETCH_TOOLS=${SKIP_FETCH_TOOLS:-""}
  if [ -n "$SKIP_FETCH_TOOLS" ]; then
    return 0
  fi

  envtest_tools_version="${ENVTEST_TOOLS_VERSION:-0.22}"
  goarch="$(go env GOARCH)"
  goos="$(go env GOOS)"

  if [[ "$goos" != "linux" && "$goos" != "darwin" ]]; then
    echo "OS '$goos' not supported. Aborting." >&2
    return 1
  fi

  header_text "installing envtest tools@${envtest_tools_version}"
  go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-$envtest_tools_version
}
