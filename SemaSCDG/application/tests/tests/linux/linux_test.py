import unittest
import json 
from itertools import zip_longest
import logging
from parameterized import parameterized
import networkx as nx
import matplotlib.pyplot as plt
import sys 
import shutil
import os
import coverage
from pympler import muppy, summary, tracker
from HTMLTestRunner import HTMLTestRunner

# TODO manon peut etre faire des tests de performance (temps, memoire, nombre d'address visité, syscalls rencontrés, etc) pour comparer les nouvelles versions de SEMA


sys.path.insert(0, '/sema-scdg/application/')

from SemaSCDG import SemaSCDG
    
LOGGER = logging.getLogger("LinuxTest")
LOGGER.setLevel(logging.INFO)

# def save_graph_as_png(graph, file_path):
#     pos = nx.spring_layout(graph)  # You can use other layout algorithms as well

#     labels      = nx.get_edge_attributes(graph, 'label')
#     node_labels = nx.get_node_attributes(graph, 'name')  # Extracting node labels
    
#     nx.draw(graph, pos, node_size=700, node_color='skyblue', font_size=8) # with_labels=True,
#     nx.draw_networkx_edge_labels(graph, pos, edge_labels=labels)
#     nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=8)  # Drawing node labels

#     plt.savefig(file_path, format="PNG", dpi=300)

def save_graph_as_png(graph, file_path):
    pos = nx.spring_layout(graph)  # You can use other layout algorithms as well

    labels = nx.get_edge_attributes(graph, 'label')
    node_labels = nx.get_node_attributes(graph, 'name')  # Extracting node labels

    nx.draw_networkx_edges(graph, pos)
    nx.draw(graph, pos, node_size=700, node_color='skyblue', font_size=8)
    nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=8)  # Drawing node labels

    # Draw edge labels manually for multiedges
    for (u, v, data) in graph.edges(data=True):
        if 'label' in data:
            edge_label = data['label']
            edge_pos = (pos[u] + pos[v]) / 2  # Position edge label at the midpoint
            plt.text(edge_pos[0], edge_pos[1], edge_label, fontsize=8, color='red', ha='center')

    plt.savefig(file_path, format="PNG", dpi=300)

    
def graph_from_json(json_data):
    nodes = json_data.get("nodes", [])
    links = json_data.get("links", [])

    g = nx.DiGraph()

    for node in nodes:
        g.add_node(node["id"], name=node["name"], addr=node["addr"], args=node.get("args", []))

    for link in links:
        g.add_edge(link["id1"], link["id2"], label=link["label"])

    return g

def compare_graphs_json(json_data1, json_data2, path1, path2):
    LOGGER.info("Graph from json I")
    g1 = graph_from_json(json_data1)
    try:
        save_graph_as_png(g1, path1.replace(".json", "json.png"))
    except Exception as e:
        LOGGER.info(e)
    LOGGER.info(g1)
    LOGGER.info("Graph from json II")
    g2 = graph_from_json(json_data2)
    try:
        save_graph_as_png(g2, path2.replace(".json", "json.png"))
    except Exception as e:
        LOGGER.info(e)
    
    LOGGER.info("Graph from json I")
    try:
        M = nx.isomorphism.GraphMatcher(g1,g2)
        isomorphic = M.is_isomorphic()
        LOGGER.info("Graph from json II")
        if isomorphic:
            return True, M.mapping
        else:
            return False, M.mapping
    except Exception as e:
        LOGGER.info(e)
        return False, None
    
def compare_graphs(graph1, graph2):
    # Convert DOT representations to networkx DiGraph objects
    LOGGER.info("Graph from DOT I")
    try:
        g1 = nx.drawing.nx_pydot.read_dot(graph1)
    except Exception as e:
        LOGGER.info(e)
        return False, None
    try:
        save_graph_as_png(g1, graph1.replace(".gv", "gv.png"))
    except Exception as e:
        LOGGER.info(e)
    LOGGER.info("Graph from DOT II")
    try:
        g2 = nx.drawing.nx_pydot.read_dot(graph2)
    except Exception as e:
        LOGGER.info(e)
        return False, None
    try:
        save_graph_as_png(g2, graph2.replace(".gv", "gv.png"))
    except Exception as e:
        LOGGER.info(e)
    # Check for isomorphism (structural equivalence)
    try:
        M = nx.isomorphism.GraphMatcher(g1,g2)
        isomorphic = M.is_isomorphic()
        LOGGER.info("Graph from DOT II")
        if isomorphic:
            return True, M.mapping
        else:
            return False, M.mapping
    except Exception as e:
        LOGGER.info(e)
        return False, None


def remove_duplicates_traces(inputs):
    traces_path = inputs
    unique_data = {}
    with open(traces_path) as json_file:
        json_data = json.load(json_file)
        for entry in json_data:
            for key, value in entry.items():
                if key.isdigit():
                    unique_data.setdefault(key, {}).update(value)

        result = [{"sections": entry["sections"]} for entry in json_data]
        result[0].update(unique_data)

    return result
    
# TODO we might not get the same results depending on the machine
# TODO check the plugin used
# TODO only make one big tests ? or multiple one
# TODO Use bigger example -> now maybe multiple parameters is useless

class TestLinuxMethods(unittest.TestCase):
    def assertSyscallsEqual(self, expected_syscall, current_syscall, msg):
        with self.subTest(msg=msg + "Syscall - name"):
            # TODO instead of assertIn maybe check if the syscall is in the list of syscall
            self.assertIn("name", expected_syscall, msg="expected_syscall[name]  not in " + str(expected_syscall))
            self.assertIn("name", current_syscall, msg="current_syscall[name]  not in " + str(current_syscall))
            self.assertEqual(expected_syscall["name"], current_syscall["name"], msg=expected_syscall["name"] +"!=" +current_syscall["name"])

        with self.subTest(msg=msg + "Syscall - args"):
            self.assertIn("args", expected_syscall, msg="expected_syscall[args]  not in " + str(expected_syscall))
            self.assertIn("args", current_syscall, msg="current_syscall[args]  not in " + str(current_syscall))
            self.assertListEqual(expected_syscall["args"], current_syscall["args"], msg=str(expected_syscall["args"]) +"!="+ str(current_syscall["args"]))

        with self.subTest(msg=msg + "Syscall - addr_func"):
            self.assertIn("addr_func", expected_syscall, msg="expected_syscall[addr_func]  not in " + str(expected_syscall))
            self.assertIn("addr_func", current_syscall, msg="current_syscall[addr_func]  not in " + str(current_syscall))
            self.assertEqual(expected_syscall["addr_func"], current_syscall["addr_func"], msg=str(expected_syscall["addr_func"]) + "!=" + str(current_syscall["addr_func"]))

        with self.subTest(msg=msg + "Syscall - addr"):
            self.assertIn("addr", expected_syscall, msg="expected_syscall[addr]  not in " + str(expected_syscall))
            self.assertIn("addr", current_syscall, msg="current_syscall[addr]  not in " + str(current_syscall))
            self.assertEqual(expected_syscall["addr"], current_syscall["addr"], msg=str(expected_syscall["addr"])+  "!=" +str(current_syscall["addr"]))

        with self.subTest(msg=msg + "Syscall - ret"):
            self.assertIn("ret", expected_syscall, msg="expected_syscall[ret]  not in " + str(expected_syscall))
            self.assertIn("ret", current_syscall, msg="current_syscall[ret]  not in " + str(current_syscall))
            self.assertEqual(expected_syscall["ret"], current_syscall["ret"], msg=str(expected_syscall["ret"])+ "!=" +str(current_syscall["ret"]))

    def assertTracesEqual(self, expected_trace, current_trace, msg):        
        with self.subTest(msg=msg + "Trace - status"):
            self.assertIn("status", expected_trace, msg="expected_trace[status]  not in " + str(expected_trace))
            self.assertIn("status", current_trace, msg="current_trace[status]  not in " + str(current_trace))
            self.assertEqual(expected_trace["status"], current_trace["status"], msg=expected_trace["status"]+ "!="+ current_trace["status"])

        # Compare the length of the trace
        with self.subTest(msg=msg + "Trace - length"):
            self.assertIn("trace", expected_trace, msg="expected_trace[trace]  not in " + str(expected_trace))
            self.assertIn("trace", current_trace, msg="current_trace[trace]  not in " + str(current_trace))
            self.assertEqual(len(expected_trace["trace"]), len(current_trace["trace"]), msg=str(len(expected_trace["trace"])) +"!="+ str(len(current_trace["trace"])))

            # Iterate over each syscall in the traces and compare them
            for i, (expected_syscall, current_syscall) in enumerate(zip_longest(expected_trace["trace"], current_trace["trace"], fillvalue=None)):
                print("*"*20)
                with self.subTest(msg=msg + f"Syscall {i}"):
                    self.assertSyscallsEqual(expected_syscall, current_syscall , msg)
                                           
    @parameterized.expand([
        # For local test testing :P
        # ("normal",       # File name
        #  "linux",        # Folder name
        #  "CDFS",         # Exploration technique used
        #  [1],          # Number of active stashes used
        #  [50],       # Timeout used
        #  [1000]   # Max steps per execution
        #  ), 
        
       ("normal",        # File name
         "linux",        # Folder name
         "CDFS",         # Exploration technique used
         [1,5],          # Number of active stashes used
         [50,300],       # Timeout used
         [1000, 10000]   # Max steps per execution
         ), 
        
        ("normal",
         "linux",
         "CBFS", 
         [1,5],         
         [50,300],       
         [1000, 10000]
         ),  
        
        ("crypto",
         "linux",
         "CDFS",         
         [1,5],          
         [50,300,3000],      
         [100000]  
         ), 
        
        ("crypto",
         "linux",
         "CBFS", 
         [1,5],         
         [50,300,3000],       
         [100000]
         ),  
    ])
    def test_linux_trace(self, 
                        file,
                        folder,
                        exploration_tech,
                        max_active_stashes, 
                        timeout, 
                        max_steps):
        """_summary_
        Test if the traces in inter_SCDG.json are the same as the expected ones.
        The traces are preprocessed to remove duplicates.
        The traces are NOT preprocessed to remove duplicates.
        
        Test if the SCDG in .json are the same as the expected ones.
        
        Args:
            exploration_tech (_type_): _description_
            max_active_stashes (_type_): _description_
            timeout (_type_): _description_
            max_steps (_type_): _description_
        """
        # root_dir = os.getcwd()
        # os.chdir(os.getcwd()+"/tests")
        # os.system("make all")
        # os.chdir(root_dir)
        
        # TODO copy the mapping file at some points, use a new one ? use the one for the expected ouputs
                 
        for active_stash in max_active_stashes:
            for time in timeout:
                for steps in max_steps:
                    LOGGER.info("*"*20)
                    LOGGER.info("TestLinuxMethods - test_linux_trace for " + file)
                    LOGGER.info("Exploration technique: " + exploration_tech)
                    LOGGER.info("Active stash: " + str(active_stash))
                    LOGGER.info("Timeout: " + str(time))
                    LOGGER.info("Max steps: " + str(steps))
                    
                    tool_scdg = SemaSCDG(
                        config_file="config_test.ini"
                    )
                                        
                    LOGGER.info("Starting running samples with parameters: " + str(tool_scdg.config))
                                        
                    tool_scdg.config.set('explorer_arg', 'max_simul_state', str(active_stash))
                    tool_scdg.config.set('explorer_arg', 'timeout',str(time))
                    tool_scdg.config.set('explorer_arg', 'max_step',str(steps))
                    tool_scdg.config.set('SCDG_arg',     'expl_method',exploration_tech)
                    
                    tool_scdg.config.set('SCDG_arg',     'binary_path',"tests/compiled_binaries/"+folder+"/"+file)
                    tool_scdg.config.set('SCDG_arg',     'exp_dir',     file)
                    tool_scdg.config.set('SCDG_arg',     'family',      folder)

                    with open("config_test.ini", 'w') as configfile:
                        tool_scdg.config.write(configfile)
                    
                    tool_scdg.get_config_param(tool_scdg.config)
                    
                    LOGGER.info("Starting running samples with parameters:" + str(tool_scdg.config))
                    
                    tool_scdg.start_scdg()
                    
                    # TODO should be in init_test_linux.py, we should run the based exploration technique from Charles-Henri and check that thre refactor ones are still correct 
                    if False:
                        expected_linux_folder_simprocedure = "/sema-scdg/application/tests/expected_output/"+folder+"/simprocedure/"
                        if not os.path.exists(expected_linux_folder_simprocedure):
                            # Copy recursively all the simprocedures from src/SemaSCDG/procedures/linux/custom_package to expected output/simprocedures
                            os.makedirs(expected_linux_folder_simprocedure)
                            for foldername, subfolders, filenames in os.walk("/sema-scdg/application/procedures/"+folder+"/custom_package"):
                                for filename in filenames:
                                    src_file  = os.path.join(foldername, filename)
                                    dest_file = os.path.join(expected_linux_folder_simprocedure, filename)
                                    shutil.copy2(src_file, dest_file)
                                    LOGGER.info(f"Copied: {src_file} to {dest_file}")
                                
                        # Copy file to expected output(TODO)
                        # Create the destination folder if it doesn't exist
                        if not os.path.exists(expected_linux_folder):
                            LOGGER.info("Create folder: " + expected_linux_folder)
                            os.makedirs(expected_linux_folder)
                        else:
                            LOGGER.info("Remove folder: " + expected_linux_folder)
                            shutil.rmtree(expected_linux_folder)
                            LOGGER.info("Create folder: " + expected_linux_folder)
                            os.makedirs(expected_linux_folder)

                        # Walk through the source folder recursively
                        LOGGER.info("Copy files from: " + args.exp_dir + "/"+file+"/")
                        for foldername, subfolders, filenames in os.walk(args.exp_dir + "/"+file+"/"):
                            for filename in filenames:
                                # Create the full path for the source and destination files
                                src_file  = os.path.join(foldername, filename)
                                dest_file = os.path.join(expected_linux_folder, os.path.relpath(src_file, args.exp_dir + "/"+file+"/"))

                                # Copy the file
                                shutil.copy2(src_file, dest_file)
                                LOGGER.info(f"Copied: {src_file} to {dest_file}")
                    
                    
                    expected_linux_folder = "/sema-scdg/application/tests/expected_output/" + folder + "/"+ file+ "_" + \
                        exploration_tech + \
                        "_" + str(active_stash) + \
                        "_" + str(time) + \
                        "_" + str(steps)
                    
                    
                    # TODO maybe use subfolder
                    expected_linux_outputs = expected_linux_folder + "/inter_SCDG.json"
                                        
                    # TODO adapt if new binaries to tests
                    current_linux_outputs = "/sema-scdg/application/database/SCDG/runs/" + tool_scdg.config["SCDG_arg"]["exp_dir"]  + "/"+ folder +"/"+ file +"/inter_SCDG.json"
                    
                    LOGGER.info("Expected output: " + expected_linux_outputs)
                    LOGGER.info("Current output : " + current_linux_outputs)
                    
                    LOGGER.info("Check unique trace: ")
                    unique_traces         = remove_duplicates_traces(expected_linux_outputs)
                    current_unique_traces = remove_duplicates_traces(current_linux_outputs)
                    for i, (trace1, trace2) in enumerate(zip_longest(unique_traces[0], current_unique_traces[0], fillvalue=None)):
                        if trace1 and "sections" in trace1:
                            LOGGER.info("Sections are not compared")
                            continue
                        with self.subTest(msg=file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - Trace Unique {i}"):
                            self.assertTracesEqual(unique_traces[0][trace1], unique_traces[0][trace2], file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - ")
                    
                    LOGGER.info("Check trace: ")
                    with open(expected_linux_outputs) as json_file:
                        unique_traces = json.load(json_file)    
                    with open(current_linux_outputs) as json_file:
                        current_unique_traces = json.load(json_file)
                    
                    for i, (trace1, trace2) in enumerate(zip_longest(unique_traces[0], current_unique_traces[0], fillvalue=None)):
                        if trace1 and "sections" in trace1:
                            LOGGER.info("Sections are not compared")
                            continue
                        with self.subTest(msg=file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - Trace {i}"):
                            self.assertTracesEqual(unique_traces[0][trace1], unique_traces[0][trace2], file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - ")
                    
                    LOGGER.info("Check json SCDG: ")
                    expected_linux_outputs = expected_linux_folder + "/"+ file  +".json"
                    
                    # TODO adapt if new binaries to tests
                    current_linux_outputs = "/sema-scdg/application/database/SCDG/runs/" + tool_scdg.config["SCDG_arg"]["exp_dir"] + "/" + folder + "/"+ file + "/final_SCDG.json"
                    
                    LOGGER.info("Expected output: " + expected_linux_outputs)
                    LOGGER.info("Current output : " + current_linux_outputs)
                    
                    with open(expected_linux_outputs) as json_file:
                        unique_traces         = json.load(json_file)    
                    with open(current_linux_outputs) as json_file:
                        current_unique_traces = json.load(json_file)
                    
                    result, mapping = compare_graphs_json(unique_traces, current_unique_traces, expected_linux_outputs, current_linux_outputs)
                    with self.subTest(msg=file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - Graph JSON - status"):
                        self.assertTrue(result, msg="Should be true but the mapping is: " + str(mapping))
                        LOGGER.info(mapping)
                          
                    LOGGER.info("Check GV SCDG: ")
                    expected_linux_outputs = expected_linux_folder + "/"+ file  +".gv"
                    
                    # TODO adapt if new binaries to tests
                    current_linux_outputs  = "/sema-scdg/application/database/SCDG/runs/" + tool_scdg.config["SCDG_arg"]["exp_dir"] + "/" + folder + "/"+ file + "/final_SCDG.gv"
                    
                    LOGGER.info("Expected output: " + expected_linux_outputs)
                    LOGGER.info("Current output : " + current_linux_outputs)
                
                    result, mapping = compare_graphs(expected_linux_outputs, current_linux_outputs)
                    with self.subTest(msg=file + "_" + \
                                                exploration_tech + \
                                                "_" + str(active_stash) + \
                                                "_" + str(time) + \
                                                "_" + str(steps) + " - Graph GV - status"):
                        self.assertTrue(result, msg="Should be true but the mapping is: " + str(mapping))
                        LOGGER.info(mapping)
                        
                    # TODO SAMY compare scdg between json and gv ?
    

# Create the test suite
def suite():
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestLinuxMethods))
    return test_suite

if __name__ == '__main__':
    # os.chdir("/sema-scdg/application/")
    cov = coverage.Coverage(source=["/sema-scdg/application/"])
    cov.start()
    #TODO manon test classic sans rapport (parametriser ?)
    # unittest.TextTestRunner(verbosity=2).run(suite())
    
     # https://ravikiranb36.github.io/htmltestrunner-rv.github.io/api-documentation/
    runner = HTMLTestRunner(
                log=True, verbosity=2, 
                output='/sema-scdg/application/tests/reports/tests_reports/', 
                title='linux_test_result', 
                report_name='Linux test report',
                open_in_browser=False,
                description="/", 
                tested_by="ElNiak",
                add_traceback=True)
    runner.run(suite())
    
    all_objects = muppy.get_objects()
    LOGGER.info(len(all_objects))
    sum1 = summary.summarize(all_objects)
    summary.print_(sum1,limit=150)
    
    tr = tracker.SummaryTracker()
    tr.print_diff() 
    
    cov.stop()
    cov.save()
    cov.html_report(directory="/sema-scdg/application/tests/reports/code_coverage/")
    
    
    # os.chdir(os.getcwd()+"/tests")
    # os.system("make clean")
    # os.chdir(os.getcwd())