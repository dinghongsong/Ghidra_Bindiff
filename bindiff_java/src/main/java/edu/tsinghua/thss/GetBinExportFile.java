package edu.tsinghua.thss;

import java.io.IOException;
import java.sql.SQLException;

public class GetBinExportFile {
    public static void main(String[] args) throws SQLException, ClassNotFoundException, IOException, InterruptedException {

        String ghidraAnalyzeHeadless = "/home/sdh/Downloads/ghidra_10.0.4_PUBLIC/support/analyzeHeadless";
        String[] command = {ghidraAnalyzeHeadless, "../auto_bindiff/", "TestProject", "-import", "../auto_bindiff/binFile/", "-deleteProject", "-scriptPath", "../auto_bindiff/", "-postScript", "../auto_bindiff/binFile_binexport.py"};
        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
