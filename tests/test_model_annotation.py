# This file is part of CycloneDX Python Library
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

import unittest
from datetime import datetime, timezone

from cyclonedx.model.annotation import Annotation, Annotator
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.service import Service


class TestAnnotator(unittest.TestCase):

    def test_init_organization(self) -> None:
        org = OrganizationalEntity(name='Acme, Inc.')
        annotator = Annotator(organization=org)
        self.assertEqual(annotator.organization, org)
        self.assertIsNone(annotator.individual)
        self.assertIsNone(annotator.component)
        self.assertIsNone(annotator.service)

        # Test setter
        org2 = OrganizationalEntity(name='Beta, Inc.')
        annotator.organization = org2
        self.assertEqual(annotator.organization, org2)

    def test_init_individual(self) -> None:
        contact = OrganizationalContact(name='John Doe')
        annotator = Annotator(individual=contact)
        self.assertEqual(annotator.individual, contact)

        # Test setter
        contact2 = OrganizationalContact(name='Jane Doe')
        annotator.individual = contact2
        self.assertEqual(annotator.individual, contact2)

    def test_init_component(self) -> None:
        comp = Component(name='MyComponent')
        annotator = Annotator(component=comp)
        self.assertEqual(annotator.component, comp)

        # Test setter
        comp2 = Component(name='OtherComponent')
        annotator.component = comp2
        self.assertEqual(annotator.component, comp2)

    def test_init_service(self) -> None:
        svc = Service(name='MyService')
        annotator = Annotator(service=svc)
        self.assertEqual(annotator.service, svc)

        # Test setter
        svc2 = Service(name='OtherService')
        annotator.service = svc2
        self.assertEqual(annotator.service, svc2)

    def test_init_invalid(self) -> None:
        with self.assertRaises(ValueError):
            Annotator()

        with self.assertRaises(ValueError):
            Annotator(organization=OrganizationalEntity(name='A'), individual=OrganizationalContact(name='B'))

    def test_eq_and_hash(self) -> None:
        org = OrganizationalEntity(name='Acme')
        a1 = Annotator(organization=org)
        a2 = Annotator(organization=org)
        a3 = Annotator(individual=OrganizationalContact(name='John'))

        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, a3)
        self.assertNotEqual(a1, 'NotAnAnnotator')

        self.assertEqual(hash(a1), hash(a2))
        self.assertNotEqual(hash(a1), hash(a3))


class TestAnnotation(unittest.TestCase):

    def setUp(self) -> None:
        self.annotator = Annotator(organization=OrganizationalEntity(name='Acme'))
        self.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.subjects = [BomRef(value='subject-1')]

    def test_init_basic(self) -> None:
        annotation = Annotation(
            bom_ref='anno-1',
            subjects=self.subjects,
            annotator=self.annotator,
            timestamp=self.timestamp,
            text='A test annotation'
        )

        self.assertEqual(annotation.bom_ref.value, 'anno-1')
        self.assertEqual(list(annotation.subjects)[0].value, 'subject-1')
        self.assertEqual(annotation.annotator, self.annotator)
        self.assertEqual(annotation.timestamp, self.timestamp)
        self.assertEqual(annotation.text, 'A test annotation')

        # Test setters
        annotation.bom_ref = BomRef(value='anno-2')
        self.assertEqual(annotation.bom_ref.value, 'anno-2')

        annotation.subjects = [BomRef(value='subject-2')]
        self.assertEqual(list(annotation.subjects)[0].value, 'subject-2')

        a2 = Annotator(individual=OrganizationalContact(name='John'))
        annotation.annotator = a2
        self.assertEqual(annotation.annotator, a2)

        t2 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        annotation.timestamp = t2
        self.assertEqual(annotation.timestamp, t2)

        annotation.text = 'New text'
        self.assertEqual(annotation.text, 'New text')

    def test_eq_and_hash(self) -> None:
        a1 = Annotation(
            bom_ref='anno-1',
            subjects=self.subjects,
            annotator=self.annotator,
            timestamp=self.timestamp,
            text='Text'
        )

        a2 = Annotation(
            bom_ref='anno-1',
            subjects=self.subjects,
            annotator=self.annotator,
            timestamp=self.timestamp,
            text='Text'
        )

        a3 = Annotation(
            bom_ref='anno-1',
            subjects=self.subjects,
            annotator=self.annotator,
            timestamp=self.timestamp,
            text='Different Text'
        )

        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, a3)
        self.assertNotEqual(a1, 'NotAnAnnotation')

        self.assertEqual(hash(a1), hash(a2))
        self.assertNotEqual(hash(a1), hash(a3))


if __name__ == '__main__':
    unittest.main()
