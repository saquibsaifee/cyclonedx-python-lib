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

Validation
==========

The CycloneDX Python Library can be utilized purely for validation purposes without requiring the instantiation of the internal CycloneDX models or performing serialization/deserialization workflows. This is highly beneficial for use cases where an application simply needs to verify if an incoming Bill of Materials (BOM) conforms to the official CycloneDX specifications.

Validating raw strings or files directly improves efficiency and guarantees schema compliance, enabling seamless integration into APIs, ingestion pipelines, or CI/CD systems where validation is a strict prerequisite before downstream processing.

The library supports validating both JSON and XML BOMs against multiple CycloneDX schema versions and provides detailed error reporting (such as JSON path and error message) when validation fails.

For a comprehensive code example of pure validation covering both JSON and XML formats, dynamic version detection, and detailed error handling, refer to the `Validation Examples <examples.html#complex-validation>`_ or look at the example script directly:

.. literalinclude:: ../examples/complex_validation.py
   :language: python
   :linenos:
