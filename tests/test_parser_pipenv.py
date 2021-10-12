# encoding: utf-8

# This file is part of CycloneDX Python Lib
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
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

import os
from unittest import TestCase

from cyclonedx.parser.pipenv import PipEnvFileParser


class TestPipEnvParser(TestCase):

    def test_simple(self):
        tests_pipfile_lock = os.path.join(os.path.dirname(__file__), 'fixtures/pipfile-lock-simple.txt')

        parser = PipEnvFileParser(pipenv_lock_filename=tests_pipfile_lock)
        self.assertEqual(1, parser.component_count())
        components = parser.get_components()
        self.assertEqual('toml', components[0].get_name())
        self.assertEqual('0.10.2', components[0].get_version())
        self.assertEqual(len(components[0].get_external_references()), 2)
        self.assertEqual(len(components[0].get_external_references()[0].get_hashes()), 1)