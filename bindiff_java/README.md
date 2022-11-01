# Requirements
- [ghidra 10.0.4](https://github.com/NationalSecurityAgency/ghidra/releases)
- [bindiff5](https://www.zynamics.com/software.html)
- java 17
# Usage
## step 1
- change the __ghidraAnalyzeHeadless__ path in ./bindiff_java/src/main/java/edu/tsinghua/thss/GetBinExportFile.java
- change the __bindiff__ path in ./bindiff_java/src/main/java/edu/tsinghua/thss/Main.java
- change the __bindiff_output_dir__ Path as your .bindiff files directory
## step 2
- run ./bindiff_java/src/main/java/edu/tsinghua/thss/GetBinExportFile.java to get BinExport files
## step 3
- run ./bindiff_java/src/main/java/edu/tsinghua/thss/Main.java to get the result of comparison