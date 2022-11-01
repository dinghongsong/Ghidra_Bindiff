package edu.tsinghua.thss;

import com.alibaba.fastjson.JSON;
import com.google.security.zynamics.AutoBindiff;
import com.google.security.zynamics.BinExportFilter;
import edu.tsinghua.thss.utils.Constants;
import edu.tsinghua.thss.utils.DataSetJSONObj;
import edu.tsinghua.thss.utils.ExeAnalysisJSONObj;

import java.io.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws SQLException, ClassNotFoundException, IOException, InterruptedException {

        String bindiff = "/home/sdh/Downloads/bindiff5/opt/bindiff/bin/bindiff";
        String bindiff_output_dir ="/home/sdh/Ghidra_Bindiff/auto_bindiff/bindiffFile/";
        double fs_th = 0.2; // function similarity thresold
        double fc_th = 0.2; // function confidence thresold



        // load json
        List<DataSetJSONObj.BinFileDataSet> binFileDataSet;
        try {
            String jsonStr = Files.readString(Paths.get(Constants.AUTO_BINDIFF_DIR, "data2.json"), StandardCharsets.UTF_8);
            DataSetJSONObj dataJsonObj = JSON.parseObject(jsonStr, DataSetJSONObj.class);
            binFileDataSet = dataJsonObj.getBinFileDataSet();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }


        for (DataSetJSONObj.BinFileDataSet fileDataSet : binFileDataSet) {
            AutoBindiff autoBindiff = new AutoBindiff(fileDataSet.getPrimary(), fileDataSet.getSecondary(), fileDataSet.getLabel()
                    , bindiff_output_dir, bindiff, fs_th, fc_th);
            autoBindiff.checkSimilarity();
        }


    }
}
