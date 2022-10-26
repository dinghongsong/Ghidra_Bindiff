package com.google.security.zynamics;

import edu.tsinghua.thss.utils.Constants;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class AutoBindiff{
    private final String ghidraAnalyzeHeadless;
    private final String primary;
    private final String secondary;
    private final String label;
    private final String bindiff_output_dir;
    private final String bindiff;
    private final double fs_th; // function similarity thresold
    private final double fc_th; // confidence similarity thresold




    public AutoBindiff(String ghidraAnalyzeHeadless, String primary, String secondary, boolean label, String bindiff_output_dir, String bindiff, double fs_th, double fc_th) throws IOException {
        this.ghidraAnalyzeHeadless = ghidraAnalyzeHeadless;
        this.primary = primary;
        this.secondary = secondary;
        this.label = Boolean.toString(label);
        this.bindiff = bindiff;
        this.bindiff_output_dir = bindiff_output_dir;
        this.fc_th = fc_th;
        this.fs_th = fs_th;
    }
    public void checkSimilarity() throws SQLException, ClassNotFoundException {
        Path pri_filter_binexp = this.getFilteredBinExport(this.primary);
        Path sec_filter_binexp = this.getFilteredBinExport(this.secondary);
        String bindiffFilePath = this.getBindiff(pri_filter_binexp, sec_filter_binexp);
        this.calculateReuseScore(bindiffFilePath);
    }


    public Path getFilteredBinExport(String binFile){
        Path binexp = Paths.get(Constants.AUTO_BINDIFF_DIR,"binexportFile", binFile+".BinExport");
        BinExportFilter filter = new BinExportFilter(binexp, 0);
        return  filter.filter();
    }

    public String getBindiff(Path primary, Path secondary){
        String bindiffFilePath = this.bindiff_output_dir + primary.toString().split("/")[primary.toString().split("/").length - 1].replaceAll(".BinExport", "") + "_vs_" + secondary.toString().split("/")[secondary.toString().split("/").length - 1].replaceAll(".BinExport", "") + ".BinDiff";
        String[] cmd = {bindiff, primary.toString(), secondary.toString(), "--output_dir=" + this.bindiff_output_dir};

        try {
            Process exec = Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bindiffFilePath;

    }

    public void calculateReuseScore(String bindiffFilePath) throws ClassNotFoundException, SQLException {

        Class.forName("org.sqlite.JDBC");
        Connection c = DriverManager.getConnection("jdbc:sqlite:" + bindiffFilePath);
//        System.out.println("Opened database successfully");
        Statement statement = c.createStatement();
        ResultSet matched_func = statement.executeQuery("SELECT COUNT(*) FROM function WHERE similarity > %f and confidence > %f".formatted(this.fs_th, this.fc_th));

        // the size of match function
        matched_func.next();
        float matched_cnt = matched_func.getInt(1);

        ResultSet total_func = statement.executeQuery("SELECT functions,libfunctions FROM file");


        total_func.next();
        int total_func_primary = total_func.getInt("functions") + total_func.getInt("libfunctions");
        total_func.next();
        int total_func_secondary = total_func.getInt("functions") + total_func.getInt("libfunctions");
        statement.close();
        c.close();

        System.out.printf(this.primary + " has %d functions, matched proportion: %f%n", total_func_primary, matched_cnt/total_func_primary);
        System.out.printf(this.secondary + " has %d functions, matched proportion: %f%n", total_func_secondary, matched_cnt/total_func_secondary);
        System.out.println("label: " + this.label);


    }



}
