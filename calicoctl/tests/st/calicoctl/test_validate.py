# Copyright (c) 2019 Tigera, Inc. All rights reserved.
#
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
import json
import logging
import copy

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

licenses_dir = "test-data/licenses/"
v3_dir = "test-data/v3/"

class TestCalicoctlValidate(TestBase):
    """
    Test calicoctl validate license extension (only in Enterprise).
    """

    def test_validate_license(self):
        """
        Test license validation operation are handled correctly.
        - Expect success for expired, but valid license
        - Expect error for corrupt license (and non-zero exit code)
        - Expect error for non-license manifest (and non-zero exit code)
        - Expect success for valid license
        """
        rc = calicoctl("validate -f %s" % (licenses_dir + "expired-production-license.yaml"))
        rc.assert_no_error()

        rc = calicoctl("validate -f %s" % (licenses_dir + "corrupt-license.yaml"))
        rc.assert_error()

        rc = calicoctl("validate -f %s" % (v3_dir + "networkpolicy.yaml"))
        rc.assert_error()

        rc = calicoctl("validate -f %s" % self.find_valid_license())
        rc.assert_no_error()
