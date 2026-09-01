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

from collections.abc import Iterable
from datetime import datetime
from typing import Optional

import py_serializable as serializable
from py_serializable.helpers import XsdDateTime
from sortedcontainers import SortedSet

from .bom_ref import BomRef
from .component import Component
from .contact import OrganizationalContact, OrganizationalEntity
from .service import Service


@serializable.serializable_class
class Annotator:
    """
    The organization, person, component, or service which created the textual content of the annotation.
    """

    def __init__(
        self, *,
        organization: Optional[OrganizationalEntity] = None,
        individual: Optional[OrganizationalContact] = None,
        component: Optional[Component] = None,
        service: Optional[Service] = None,
    ) -> None:
        if sum(x is not None for x in (organization, individual, component, service)) != 1:
            raise ValueError('Exactly one of organization, individual, component, or service must be provided.')

        self.organization = organization
        self.individual = individual
        self.component = component
        self.service = service

    @property
    @serializable.xml_sequence(1)
    def organization(self) -> Optional[OrganizationalEntity]:
        return self._organization

    @organization.setter
    def organization(self, organization: Optional[OrganizationalEntity]) -> None:
        self._organization = organization

    @property
    @serializable.xml_sequence(2)
    def individual(self) -> Optional[OrganizationalContact]:
        return self._individual

    @individual.setter
    def individual(self, individual: Optional[OrganizationalContact]) -> None:
        self._individual = individual

    @property
    @serializable.xml_sequence(3)
    def component(self) -> Optional[Component]:
        return self._component

    @component.setter
    def component(self, component: Optional[Component]) -> None:
        self._component = component

    @property
    @serializable.xml_sequence(4)
    def service(self) -> Optional[Service]:
        return self._service

    @service.setter
    def service(self, service: Optional[Service]) -> None:
        self._service = service

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Annotator):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((self.organization, self.individual, self.component, self.service))


@serializable.serializable_class
class Annotation:
    """
    A comment, note, explanation, or similar textual content which provides additional context
    to the object(s) being annotated.
    """

    def __init__(
        self, *,
        subjects: Iterable[BomRef],
        annotator: Annotator,
        timestamp: datetime,
        text: str,
        bom_ref: Optional[str] = None,
    ) -> None:
        self.bom_ref = BomRef(value=bom_ref) if bom_ref else BomRef()
        self.subjects = subjects
        self.annotator = annotator
        self.timestamp = timestamp
        self.text = text

    @property
    @serializable.xml_attribute()
    @serializable.type_mapping(serializable.helpers.BaseHelper)
    def bom_ref(self) -> BomRef:
        """
        An optional identifier which can be used to reference the annotation elsewhere in the BOM.
        """
        return self._bom_ref

    @bom_ref.setter
    def bom_ref(self, bom_ref: BomRef) -> None:
        self._bom_ref = bom_ref

    @property
    @serializable.xml_array(serializable.XmlArraySerializationType.FLAT, 'subject')
    @serializable.xml_sequence(1)
    def subjects(self) -> 'SortedSet[BomRef]':
        """
        The object in the BOM identified by its bom-ref.
        """
        return self._subjects

    @subjects.setter
    def subjects(self, subjects: Iterable[BomRef]) -> None:
        self._subjects = SortedSet(subjects)

    @property
    @serializable.xml_sequence(2)
    def annotator(self) -> Annotator:
        """
        The organization, person, component, or service which created the textual content of the annotation.
        """
        return self._annotator

    @annotator.setter
    def annotator(self, annotator: Annotator) -> None:
        self._annotator = annotator

    @property
    @serializable.type_mapping(XsdDateTime)
    @serializable.xml_sequence(3)
    def timestamp(self) -> datetime:
        """
        The date and time (timestamp) when the annotation was created.
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: datetime) -> None:
        self._timestamp = timestamp

    @property
    @serializable.xml_sequence(4)
    def text(self) -> str:
        """
        The textual content of the annotation.
        """
        return self._text

    @text.setter
    def text(self, text: str) -> None:
        self._text = text

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Annotation):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash((self.bom_ref, tuple(self.subjects), self.annotator, self.timestamp, self.text))
