.. # Licensed under the Apache License, Version 2.0 (the "License");
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

Validating
===========================

Overview
--------

The CycloneDX Python library provides robust validation capabilities to ensure your Software Bill of Materials (SBOM) documents conform to the CycloneDX specification. This guide demonstrates how to validate SBOMs effectively in various scenarios, from simple validation checks to production API integrations.

Why Validate SBOMs?
~~~~~~~~~~~~~~~~~~~~

Validation ensures that:

* Your SBOM conforms to the CycloneDX schema specification
* All required fields are present and correctly formatted
* Data types and structures match the specification
* The SBOM can be reliably consumed by other tools and systems

Basic Validation
----------------

Validating JSON SBOMs
~~~~~~~~~~~~~~~~~~~~~

The most common use case is validating a JSON-formatted SBOM:

.. code-block:: python

    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
    import json

    # Create a validator for CycloneDX 1.5
    validator = JsonValidator(SchemaVersion.V1_5)

    # Load your SBOM
    with open('sbom.json', 'r') as f:
        sbom_data = f.read()

    # Validate the SBOM
    validation_error = validator.validate_str(sbom_data)

    if validation_error:
        print(f"❌ Validation failed!")
        print(f"Error: {validation_error}")
    else:
        print("✅ SBOM is valid!")

Validating from Dictionary
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you already have your SBOM as a Python dictionary:

.. code-block:: python

    import json
    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion

    sbom_dict = {
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

    validator = JsonValidator(SchemaVersion.V1_5)
    validation_error = validator.validate_str(json.dumps(sbom_dict))

    if not validation_error:
        print("✅ SBOM is valid!")

Understanding Validation Errors
--------------------------------

When validation fails, the library provides detailed error information to help you identify and fix issues.

Accessing Error Details
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
    import json

    validator = JsonValidator(SchemaVersion.V1_5)

    # Invalid SBOM (missing required fields)
    invalid_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        # Missing 'version' field (required)
    }

    validation_error = validator.validate_str(json.dumps(invalid_sbom))

    if validation_error:
        # Access the validation error details
        print(f"Error message: {validation_error.message}")
        print(f"Invalid data: {validation_error.data.instance}")
        print(f"JSON path: {validation_error.data.json_path}")

Error Object Structure
~~~~~~~~~~~~~~~~~~~~~~

The ``ValidationError`` object provides:

* **message**: Human-readable error description
* **data.instance**: The actual invalid data that caused the error
* **data.json_path**: JSONPath to the location of the error in the document

Detailed Error Logging Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import logging
    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
    import json

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    def validate_with_logging(sbom_dict: dict, schema_version: SchemaVersion) -> bool:
        """Validate SBOM with detailed error logging."""
        validator = JsonValidator(schema_version)
        validation_error = validator.validate_str(json.dumps(sbom_dict))
        
        if validation_error:
            logger.error("SBOM validation failed")
            logger.error(f"Location: {validation_error.data.json_path}")
            logger.error(f"Invalid data: {validation_error.data.instance}")
            logger.error(f"Message: {validation_error.message}")
            return False
        
        logger.info("SBOM validation successful")
        return True

    # Usage
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}
    is_valid = validate_with_logging(sbom, SchemaVersion.V1_5)

Multi-Version Support
---------------------

The CycloneDX specification has multiple versions. Your application should handle different versions gracefully.

Dynamic Version Detection
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
    import json

    def validate_sbom_any_version(sbom_dict: dict) -> tuple[bool, str | None]:
        """
        Validate SBOM with automatic version detection.
        
        Args:
            sbom_dict: SBOM as a dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Map spec versions to SchemaVersion enums
        version_map = {
            "1.2": SchemaVersion.V1_2,
            "1.3": SchemaVersion.V1_3,
            "1.4": SchemaVersion.V1_4,
            "1.5": SchemaVersion.V1_5,
            "1.6": SchemaVersion.V1_6,
        }
        
        # Get the spec version from SBOM
        spec_version = sbom_dict.get("specVersion")
        
        if not spec_version:
            return False, "Missing 'specVersion' field"
        
        if spec_version not in version_map:
            return False, f"Unsupported CycloneDX version: {spec_version}"
        
        # Validate with the appropriate schema version
        validator = JsonValidator(version_map[spec_version])
        validation_error = validator.validate_str(json.dumps(sbom_dict))
        
        if validation_error:
            error_msg = f"Validation failed at {validation_error.data.json_path}: {validation_error.message}"
            return False, error_msg
        
        return True, None

    # Usage
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",  # Will automatically use V1_4 validator
        "version": 1
    }

    is_valid, error = validate_sbom_any_version(sbom)
    if is_valid:
        print("✅ SBOM is valid!")
    else:
        print(f"❌ Validation failed: {error}")

Validating XML SBOMs
--------------------

CycloneDX also supports XML format. The validation process is similar to JSON:

.. code-block:: python

    from cyclonedx.validation.xml import XmlValidator
    from cyclonedx.schema import SchemaVersion

    # Create XML validator
    validator = XmlValidator(SchemaVersion.V1_5)

    # Load XML SBOM
    with open('sbom.xml', 'r') as f:
        xml_data = f.read()

    # Validate
    validation_error = validator.validate_str(xml_data)

    if validation_error:
        print(f"❌ XML validation failed: {validation_error}")
    else:
        print("✅ XML SBOM is valid!")

Auto-detecting Format
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.validation.xml import XmlValidator
    from cyclonedx.schema import SchemaVersion

    def validate_sbom_file(file_path: str, schema_version: SchemaVersion = SchemaVersion.V1_5) -> bool:
        """Validate SBOM file (auto-detect JSON or XML)."""
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Determine format by file extension or content
        if file_path.endswith('.xml'):
            validator = XmlValidator(schema_version)
        else:  # Assume JSON
            validator = JsonValidator(schema_version)
        
        validation_error = validator.validate_str(content)
        return validation_error is None

    # Usage
    is_valid_json = validate_sbom_file('sbom.json')
    is_valid_xml = validate_sbom_file('sbom.xml')

Production Integration Examples
--------------------------------

FastAPI Integration
~~~~~~~~~~~~~~~~~~~

Here's how to integrate validation into a FastAPI application:

.. code-block:: python

    from fastapi import FastAPI, HTTPException, UploadFile, File, status
    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
    import json
    from typing import Any

    app = FastAPI()

    def validate_sbom_schema(sbom_data: dict[str, Any]) -> None:
        """
        Validate CycloneDX SBOM schema.
        
        Args:
            sbom_data: SBOM as dictionary
            
        Raises:
            HTTPException: If validation fails
        """
        # Map of supported versions
        schema_version_map = {
            "1.4": SchemaVersion.V1_4,
            "1.5": SchemaVersion.V1_5,
            "1.6": SchemaVersion.V1_6,
        }
        
        # Get spec version
        spec_version = sbom_data.get("specVersion")
        
        # Check if version is supported
        if spec_version not in schema_version_map:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported CycloneDX schema version: {spec_version}"
            )
        
        # Validate against schema
        try:
            validator = JsonValidator(schema_version_map[spec_version])
            validation_error = validator.validate_str(json.dumps(sbom_data))
            
            if validation_error:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail={
                        "message": "Invalid CycloneDX SBOM",
                        "location": validation_error.data.json_path,
                        "invalid_data": str(validation_error.data.instance)[:200]
                    }
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Validation error: {str(e)}"
            )

    @app.post("/validate-sbom")
    async def validate_sbom_endpoint(file: UploadFile = File(...)):
        """Endpoint to validate uploaded SBOM."""
        try:
            # Read and parse JSON
            content = await file.read()
            sbom_data = json.loads(content)
            
            # Validate schema
            validate_sbom_schema(sbom_data)
            
            return {
                "status": "valid",
                "message": "SBOM is valid",
                "version": sbom_data.get("specVersion")
            }
            
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON format"
            )


Best Practices
--------------

1. Always Validate Before Processing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    def process_sbom(sbom_data: dict) -> None:
        """Process SBOM only after validation."""
        # Validate first
        validator = JsonValidator(SchemaVersion.V1_5)
        validation_error = validator.validate_str(json.dumps(sbom_data))
        
        if validation_error:
            raise ValueError(f"Invalid SBOM: {validation_error.message}")
        
        # Now safe to process
        components = sbom_data.get("components", [])
        # ... process components

2. Use Appropriate Error Codes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In APIs, use standard HTTP status codes:

* **400 Bad Request**: Invalid JSON format, unsupported version
* **422 Unprocessable Entity**: Valid JSON but invalid CycloneDX schema
* **500 Internal Server Error**: Unexpected validation errors

3. Log Validation Errors with Context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import logging

    logger = logging.getLogger(__name__)

    def validate_with_logging(sbom_data: dict, context: dict) -> bool:
        """Validate with contextual logging."""
        validator = JsonValidator(SchemaVersion.V1_5)
        validation_error = validator.validate_str(json.dumps(sbom_data))
        
        if validation_error:
            logger.error(
                "SBOM validation failed",
                extra={
                    "context": context,
                    "error_location": validation_error.data.json_path,
                    "error_message": validation_error.message,
                    "spec_version": sbom_data.get("specVersion")
                }
            )
            return False
        
        logger.info("SBOM validation successful", extra={"context": context})
        return True

Summary
-------

Key takeaways for SBOM validation:

* ✅ Always validate SBOMs before processing
* ✅ Handle errors gracefully with detailed logging
* ✅ Support multiple versions with dynamic detection
* ✅ Use appropriate error codes in APIs (400, 422, 500)
* ✅ Provide helpful error messages to users
* ✅ Test validation logic thoroughly
* ✅ Cache validators for better performance

The CycloneDX Python library provides robust validation capabilities that can be integrated into various applications, from simple scripts to production APIs.

Additional Resources
--------------------

* `CycloneDX Specification <https://cyclonedx.org/specification/overview/>`_
* `SPDX License List <https://spdx.org/licenses/>`_
* `JSON Schema Validation <https://json-schema.org/>`_