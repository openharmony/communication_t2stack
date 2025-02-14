#!/bin/bash
# Copyright (c) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

repo init -u https://gitee.com/openharmony/manifest.git -b master --no-repo-verify
repo sync -c build

hb help
if [$? -eq 0]; then
  echo "hb is installed"
else
  echo "need to install hb!"
  python3 -m pip install --user build/hb
  echo "export PATH=~/.local/bin:$PATH" >> ~/.bashrc
  source ~/.bashrc
fi

bash build/prebuilts_config.sh
hb build t2stack -i