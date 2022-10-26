package edu.tsinghua.thss.utils;

import java.util.ArrayList;
import java.util.List;

public class ExeAnalysisJSONObj {
    private List<String> exportFunctionNames = new ArrayList<>();
    private List<String> importFunctionNames = new ArrayList<>();
    private String fileName;
    private String filePath;
    private String fileType;
    // SUCK object
    // private List<Object> functions;
    // SUCK object
    // private List<Object> stringConstants;

    public List<String> getExportFunctionNames() {
        return exportFunctionNames;
    }

    public void setExportFunctionNames(List<String> exportFunctionNames) {
        this.exportFunctionNames = exportFunctionNames;
    }

    public List<String> getImportFunctionNames() {
        return importFunctionNames;
    }

    public void setImportFunctionNames(List<String> importFunctionNames) {
        this.importFunctionNames = importFunctionNames;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
}
