# Python Library for generating CycloneDX

[![CircleCI](https://circleci.com/gh/sonatype-nexus-community/cyclonedx-python-lib.svg?style=shield)](https://circleci.com/gh/sonatype-nexus-community/cyclonedx-python-lib)

This CycloneDX module for Python can generate valid CycloneDX bill-of-material document containing an aggregate of all
project dependencies.

This module is not designed for standalone use. If you're looking for a tool to run to generate CycloneDX software
bill-of-materials documents, why not checkout:

- [Jake](https://github.com/sonatype-nexus-community/jake)

Or you can use this module yourself in your application to generate SBOMs.

CycloneDX is a lightweight BOM specification that is easily created, human-readable, and simple to parse.

## Installation

Install from pypi.org as you would any other Python module:

```
pip install cyclonedx-python-lib
```

## Architecture

This module break out into three key areas:

1. **Parser**: Use a parser that suits your needs to automatically gather information about your environment or
   application
2. **Model**: Internal models used to unify data from different parsers
3. **Output**: Choose and configure an output which allows you to define output format as well as the CycloneDX schema
   version

### Parsing

You can use one of the parsers to obtain information about your project or environment. Available parsers:

| Parser | Class / Import | Description |
| ------- | ------ | ------ |
| Environment | `from cyclonedx.parser.environment import EnvironmentParser` | Looks at the packaged installed in your current Python environment. |
| RequirementsParser | `from cyclonedx.parser.requirements import RequirementsParser` | Parses a multiline string that you provide that conforms to the `requirements.txt` [PEP-508](https://www.python.org/dev/peps/pep-0508/) standard. |
| RequirementsFileParser | `from cyclonedx.parser.requirements import RequirementsFileParser` | Parses a file that you provide the path to that conforms to the `requirements.txt` [PEP-508](https://www.python.org/dev/peps/pep-0508/) standard. |

#### Example

```
from cyclonedx.parser.environment import EnvironmentParser

parser = EnvironmentParser()
```

### Modelling

You can create a BOM Model from either an Parser instance or manually using the methods avaialbel directly on the `Bom` class.

#### Example from a Parser

```
from cyclonedx.model.bom import Bom
from cyclonedx.parser.environment import EnvironmentParser

parser = EnvironmentParser()
bom = Bom.from_parser(parser=parser)
```

### Generating Output

Once you have an instance of a `Bom` you can produce output in either `JSON` or `XML` against any of the supporting CycloneDX schema versions as you require.

We provide two helper methods:
1. Output to string (for you to do with as you require)
2. Output directly to a filename you provide

#### Supported Schema Versions

| Schema Version | JSON | XML | Notes |
| ---- | ---- | ---- | ---- |
| 1.3 _(current)_ | Y | Y | |
| 1.2 | Y | Y | |

##### Example as JSON

```
from cyclonedx.output import get_instance, OutputFormat

outputter = get_instance(bom=bom, output_format=OutputFormat.JSON)
outputter.output_as_string()
```

##### Example as XML
```
from cyclonedx.output import get_instance, SchemaVersion

outputter = get_instance(bom=bom, schema_version=SchemaVersion.V1_)
outputter.output_to_file(filename='/tmp/sbom-v1.2.xml')
```

## The Fine Print

Remember:

It is worth noting that this is **NOT SUPPORTED** by Sonatype, and is a contribution of ours to the open source
community (read: you!)

* Use this contribution at the risk tolerance that you have
* Do NOT file Sonatype support tickets related to `cyclonedx-python-lib` support in regard to this project
* DO file issues here on GitHub, so that the community can pitch in

Phew, that was easier than I thought. Last but not least of all - have fun!

