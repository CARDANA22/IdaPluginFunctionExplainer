# IDA Pro LLM Plugin

This IDA Pro plugin integrates with OpenAI's API to provide comments for functions in a binary. It extracts pseudocode from IDA, sends it to OpenAI for analysis, and then displays the returned comments in IDA.

## Features

- **Pseudocode Extraction**: Extracts pseudocode from IDA for analysis.
- **OpenAI Integration**: Seamlessly integrates with OpenAI's API.
- **Function Comments**: Provides insightful comments for functions in a binary.
- **In-IDA Display**: Displays comments directly in IDA for easy reference.

## Installation

1. Clone this repository or download the plugin files.
2. Place the plugin files in the IDA Pro plugins directory.
3. Add your API key in ine 65
4. You can change the Endpoint link in the line above that, if you don't want a chat model
5. You can also change the model in line 98
6. Restart IDA Pro to load the new plugin.

## Usage

1. Open a binary in IDA Pro.
2. Activate the plugin from the plugins menu.
3. The plugin will extract pseudocode, send it to OpenAI for analysis, and display the returned comments in IDA.

## Screenshots

*Coming soon...*

## License

MIT License
