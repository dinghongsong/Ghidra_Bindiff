package edu.tsinghua.thss.utils;

import java.util.ArrayList;
import java.util.List;

public class DataSetJSONObj {
    public List<BinFileDataSet> getBinFileDataSet() {
        return binFileDataSet;
    }

    public void setBinFileDataSet(List<BinFileDataSet> binFileDataSet) {
        this.binFileDataSet = binFileDataSet;
    }

    private List<BinFileDataSet> binFileDataSet = new ArrayList<>();

    public static class BinFileDataSet {
        private String primary;
        private String secondary;
        private Boolean label;

        public String getPrimary() {
            return primary;
        }

        public void setPrimary(String primary) {
            this.primary = primary;
        }

        public String getSecondary() {
            return secondary;
        }

        public void setSecondary(String secondary) {
            this.secondary = secondary;
        }

        public Boolean getLabel() {
            return label;
        }

        public void setLabel(Boolean label) {
            this.label = label;
        }
    }

}