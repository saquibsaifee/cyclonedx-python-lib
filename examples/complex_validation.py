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

import json
import sys
from typing import TYPE_CHECKING

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

if TYPE_CHECKING:
    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.validation.xml import XmlValidator

"""
This example demonstrates how to validate CycloneDX SBOMs (both JSON and XML).
Validation is built upon `jsonschema` for JSON and `lxml` for XML.
To use validation, ensure you have installed the library with the validation extra:
  pip install cyclonedx-python-lib[validation]
  or
  pip install cyclonedx-python-lib[json-validation,xml-validation]
"""

# region Sample SBOMs

JSON_SBOM = """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": []
}
"""

XML_SBOM = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <component type="application">
      <name>my-app</name>
      <version>1.0.0</version>
    </component>
  </metadata>
</bom>
"""

INVALID_JSON_SBOM = """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "invalid-type",
      "name": "my-app"
    }
  }
}
"""
# endregion Sample SBOMs


# region JSON Validation

print('--- JSON Validation ---')

# Create a JSON validator for a specific schema version
json_validator: 'JsonValidator' = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_5)

try:
    # 1. Validate valid SBOM
    validation_errors = json_validator.validate_str(JSON_SBOM)
    if validation_errors:
        print('JSON SBOM is unexpectedly invalid!', file=sys.stderr)
    else:
        print('JSON SBOM is valid')

    # 2. Validate invalid SBOM and inspect details
    print('\nChecking invalid JSON SBOM...')
    validation_errors = json_validator.validate_str(INVALID_JSON_SBOM)
    if validation_errors:
        print('Validation failed as expected.')
        print(f'Error Message: {validation_errors.message}')
        print(f'JSON Path:     {validation_errors.data.json_path}')
        print(f'Invalid Data:  {validation_errors.data.instance}')
except MissingOptionalDependencyException as error:
    print('JSON validation was skipped:', error)

# endregion JSON Validation


print('\n' + '=' * 30 + '\n')


# region XML Validation

print('--- XML Validation ---')

xml_validator: 'XmlValidator' = make_schemabased_validator(OutputFormat.XML, SchemaVersion.V1_5)

try:
    validation_errors = xml_validator.validate_str(XML_SBOM)
    if validation_errors:
        print('XML SBOM is invalid!', file=sys.stderr)
    else:
        print('XML SBOM is valid')
except MissingOptionalDependencyException as error:
    print('XML validation was skipped:', error)

# endregion XML Validation


print('\n' + '=' * 30 + '\n')


# region Dynamic version detection

print('--- Dynamic Validation ---')


def validate_sbom(raw_data: str) -> bool:
    """Validate an SBOM by detecting its format and version."""

    # 1. Attempt to detect JSON and its version
    try:
        data = json.loads(raw_data)
        input_format = OutputFormat.JSON
        spec_version_str = data.get('specVersion')
        if not spec_version_str:
            print('Error: Missing specVersion in JSON SBOM', file=sys.stderr)
            return False
        schema_version = SchemaVersion.from_version(spec_version_str)
    except (json.JSONDecodeError, ValueError):
        # 2. Attempt to detect XML and its version
        try:
            from lxml import etree
            xml_tree = etree.fromstring(raw_data.encode('utf-8'))
            output_format = OutputFormat.XML
            # Extract version from CycloneDX namespace
            schema_version = SchemaVersion.V1_5  # Default
            for ns in xml_tree.nsmap.values():
                if ns and ns.startswith('http://cyclonedx.org/schema/bom/'):
                    try:
                        schema_version = SchemaVersion.from_version(ns.split('/')[-1])
                        break
                    except ValueError:
                        pass
        except (ImportError, etree.XMLSyntaxError):
            print('Error: Unknown or malformed SBOM format', file=sys.stderr)
            return False
        except Exception as e:
            print(f'Error: Format detection failed: {e}', file=sys.stderr)
            return False

    # 3. Perform validation using the detected format and version
    try:
        validator = make_schemabased_validator(output_format, schema_version)
        errors = validator.validate_str(raw_data)

        if errors:
            print(f'Validation failed for {output_format.name} version {schema_version.to_version()}', file=sys.stderr)
            print(f'Reason: {errors}', file=sys.stderr)
            return False

        print(f'Successfully validated {output_format.name} SBOM (Version {schema_version.to_version()})')
        return True

    except MissingOptionalDependencyException as error:
        print(f'Validation skipped due to missing dependencies: {error}')
        return False


# Execute dynamic validation
validate_sbom(JSON_SBOM)
validate_sbom(XML_SBOM)

# endregion Dynamic version detection
