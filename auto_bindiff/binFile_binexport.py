'''
get binExport File using ghidra headless
'''

import csv
# from ghidra.app.script import GhidraScript
# from ghidra.util.task import ConsoleTaskMonitor
# from ghidra.app.decompiler import DecompileOptions, DecompInterface
# from ghidra.program.model.pcode import PcodeOp
# from ghidra.app.util.exporter import Exporter
from com.google.security.binexport import BinExportExporter
from java.io import File


addr_set = currentProgram.getMemory()
f = File('../auto_bindiff/binexportFile/' + currentProgram.getName() + '.BinExport')
exporter = BinExportExporter() #Binary BinExport (v2) for BinDiff
exporter.export(f, currentProgram, addr_set, monitor)




