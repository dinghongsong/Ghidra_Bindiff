package com.google.security.zynamics;

import com.alibaba.fastjson.JSON;
import edu.tsinghua.thss.utils.Constants;
import edu.tsinghua.thss.utils.ExeAnalysisJSONObj;
import org.apache.commons.io.FilenameUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

public class BinExportFilter {
    private final Path input_filename;
    private final int bb_th;
    private final BinExport.BinExport2 input;
    private final Map<Long, Integer> flowgraph_address = new HashMap<>();
    private final List<String> filter_name_set;

    /**
     * @param input_filename: the path of BinExport file.
     */
    public BinExportFilter(Path input_filename) {
        this(input_filename, 1);
    }

    /**
     * @param input_filename: the path of BinExport file.
     * @param bb_th:          the threshold of basic block number.
     */
    public BinExportFilter(Path input_filename, int bb_th) {
        this.input_filename = input_filename;
        this.bb_th = bb_th;
        // parse original .BinExport file
        try {
            FileInputStream fileInput = new FileInputStream(this.input_filename.toFile());
            this.input = BinExport.BinExport2.parseFrom(fileInput);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error parsing input file");
        }
        this._get_flowgraph_address();

        try {
            String jsonStr = Files.readString(Paths.get(Constants.AUTO_BINDIFF_DIR, "libc.so.6-(tw__std_lib).json"), StandardCharsets.UTF_8);
            ExeAnalysisJSONObj exeJsonObj = JSON.parseObject(jsonStr, ExeAnalysisJSONObj.class);
            this.filter_name_set = exeJsonObj.getExportFunctionNames();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public Path filter() {
        return this.filter(null);
    }

    public Path filter(Path output_filename) {
        BinExport.BinExport2.Builder new_file_builder = BinExport.BinExport2.newBuilder()
                .mergeFrom(this.input)
                .clearCallGraph()
                .clearFlowGraph();

//        System.out.printf("length of call_graph vertex: %d\n", this.input.getCallGraph().getVertexCount());

        int cnt_normal = 0;
        int cnt_lib = 0;
        int cnt_imp = 0;
        int cnt_thunk = 0;

        // filter callgraph vertex and flowgragh
        // record index map info
        int cnt_keep = 0;
        Map<Integer, Integer> callgraph_idx_map = new HashMap<>();
        List<BinExport.BinExport2.CallGraph.Vertex> vertexes = this.input.getCallGraph().getVertexList();
        // callgraph vertexes and edges' cache
        var newCallGraphBuilder = BinExport.BinExport2.CallGraph.newBuilder();
        for (int i = 0; i < vertexes.size(); i += 1) {
            BinExport.BinExport2.CallGraph.Vertex v = vertexes.get(i);
            if (this.should_keep(i)) {
                BinExport.BinExport2.CallGraph.Vertex new_v = BinExport.BinExport2.CallGraph.Vertex.newBuilder()
                        .mergeFrom(v)
                        .build();
                newCallGraphBuilder.addVertex(new_v);
                long address = new_v.getAddress();
                assert this.flowgraph_address.containsKey(address) : "cannot find flowgraph according to address";

                BinExport.BinExport2.FlowGraph new_fg = BinExport.BinExport2.FlowGraph.newBuilder()
                        .mergeFrom(this.input.getFlowGraph(this.flowgraph_address.get(address)))
                        .build();
                new_file_builder.addFlowGraph(new_fg);
                callgraph_idx_map.put(i, cnt_keep);
                cnt_keep += 1;
            }

            switch (v.getType()) {
                case NORMAL:
                    cnt_normal += 1;
                    break;
                case LIBRARY:
                    cnt_lib += 1;
                    break;
                case IMPORTED:
                    cnt_imp += 1;
                    break;
                case THUNK:
                    cnt_thunk += 1;
                    break;
                default:
                    throw new RuntimeException("unknown type of function");
            }
        }

//        System.out.printf("normal: %d\n", cnt_normal);
//        System.out.printf("library: %d\n", cnt_lib);
//        System.out.printf("imported: %d\n", cnt_imp);
//        System.out.printf("thunk: %d\n", cnt_thunk);

        assert cnt_normal + cnt_thunk == this.input.getFlowGraphCount() : "flow graph number does not equal to cnt_normal + cnt_thunk";

        // filter callgraph edge
        // use vertex index map info
        for (BinExport.BinExport2.CallGraph.Edge e : this.input.getCallGraph().getEdgeList()) {
            BooleanSupplier boolSupplier = () -> callgraph_idx_map.containsKey(e.getSourceVertexIndex())
                    && callgraph_idx_map.containsKey(e.getTargetVertexIndex());

            if (boolSupplier.getAsBoolean()) {
                var new_e = BinExport.BinExport2.CallGraph.Edge.newBuilder()
                        .setSourceVertexIndex(callgraph_idx_map.get(e.getSourceVertexIndex()))
                        .setTargetVertexIndex(callgraph_idx_map.get(e.getTargetVertexIndex()))
                        .build();
                if (!boolSupplier.getAsBoolean()) {
                    throw new RuntimeException("cannot find callgraph index map info");
                }
                newCallGraphBuilder.addEdge(new_e);
            }
        }

        // add callgraph to new file
        new_file_builder.setCallGraph(newCallGraphBuilder.build());

        if (output_filename == null) {
            String input_filename_noext = FilenameUtils.removeExtension(this.input_filename.toString());
            output_filename = Paths.get(input_filename_noext + "_filtered.BinExport");
        }
        try {
            FileOutputStream fileOutput = new FileOutputStream(output_filename.toFile());
            new_file_builder.build().writeTo(fileOutput);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error writing output file");
        }

        return output_filename;
    }

    public boolean should_keep(int idx) {
        if (this.input.getCallGraph().getVertex(idx).hasType()) {
            var type = this.input.getCallGraph().getVertex(idx).getType();
            if (type != BinExport.BinExport2.CallGraph.Vertex.Type.NORMAL) {
                return false;
            }
        }
        long address = this.input.getCallGraph().getVertex(idx).getAddress();
        int fg_idx = this.flowgraph_address.get(address);
        int bb_cnt = this.input.getFlowGraph(fg_idx).getBasicBlockIndexCount();
        if (bb_cnt <= this.bb_th) {
            return false;
        }
        String demangled_name = this.input.getCallGraph().getVertex(idx).getDemangledName();
        String mangled_name = this.input.getCallGraph().getVertex(idx).getMangledName();
        if (demangled_name.length() > 0) {
            return !this.should_filter_name(demangled_name);
        } else {
            return !this.should_filter_name(mangled_name);
        }

    }

    public boolean should_filter_name(String fun_name) {
        return fun_name.startsWith("_") || fun_name.startsWith("std::") || this.filter_name_set.contains(fun_name);
    }

    /**
     * used to link callgraph node with flowgraph, only called in constructor
     */
    public void _get_flowgraph_address() {
        for (int i = 0; i < this.input.getFlowGraphCount(); i++) {
            var fg = this.input.getFlowGraphList().get(i);
            BinExport.BinExport2.BasicBlock entry_bb = this.input.getBasicBlock(fg.getEntryBasicBlockIndex());
            int entry_ins_idx = entry_bb.getInstructionIndex(0).getBeginIndex();
            long address = this.input.getInstruction(entry_ins_idx).getAddress();
            this.flowgraph_address.put(address, i);
        }

//        System.out.format("length of flowgraph address: %d\n", this.flowgraph_address.size());
    }
}
